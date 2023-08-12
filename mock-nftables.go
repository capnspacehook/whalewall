package whalewall

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mitchellh/copystructure"
	"go.uber.org/zap"
)

const anonSetName = "__set%d"

var (
	globalFirewall *mockFirewall
	setAllocNum    = 1
)

type firewallClient interface {
	AddTable(t *nftables.Table) *nftables.Table

	AddChain(c *nftables.Chain) *nftables.Chain
	DelChain(c *nftables.Chain)
	ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error)

	AddSet(s *nftables.Set, vals []nftables.SetElement) error
	DelSet(s *nftables.Set)
	SetAddElements(s *nftables.Set, vals []nftables.SetElement) error
	SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error

	AddRule(r *nftables.Rule) *nftables.Rule
	DelRule(r *nftables.Rule) error
	InsertRule(r *nftables.Rule) *nftables.Rule
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)

	Flush() error
}

type mockFirewall struct {
	logger *zap.SugaredLogger

	changed bool

	tables map[string]*table
	chains map[string]chain

	unsetLookupExprs []*expr.Lookup

	flushErr error
}

type table struct {
	Sets setMap

	newAnonSets map[string]bool
}

type chain struct {
	Chain *nftables.Chain
	Rules []*nftables.Rule
}

type setMap map[string][]nftables.SetElement

func newMockFirewall(logger *zap.Logger) *mockFirewall {
	if globalFirewall == nil {
		globalFirewall = &mockFirewall{
			tables: make(map[string]*table),
			chains: make(map[string]chain),
		}
	}

	m := &mockFirewall{
		logger: logger.Sugar(),
		tables: clone(globalFirewall.tables),
		chains: clone(globalFirewall.chains),
	}
	initTables(m)

	return m
}

func initTables(m *mockFirewall) {
	for _, t := range m.tables {
		t.newAnonSets = make(map[string]bool)
	}
}

func (m *mockFirewall) clone() *mockFirewall {
	return &mockFirewall{
		logger: m.logger,
		tables: clone(m.tables),
		chains: clone(m.chains),
	}
}

func (m *mockFirewall) AddTable(t *nftables.Table) *nftables.Table {
	m.changed = true

	if _, ok := m.tables[t.Name]; !ok {
		m.tables[t.Name] = &table{
			Sets:        make(setMap),
			newAnonSets: make(map[string]bool),
		}
	}

	return t
}

func (m *mockFirewall) AddChain(c *nftables.Chain) *nftables.Chain {
	m.changed = true

	if _, ok := m.chains[c.Name]; !ok {
		m.chains[c.Name] = chain{
			Chain: c,
		}
	}

	return c
}

func (m *mockFirewall) DelChain(c *nftables.Chain) {
	m.changed = true

	chain, ok := m.chains[c.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", c.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	// delete rules so anonymous sets have a chance to get cleaned up
	for _, rule := range chain.Rules {
		m.delRule(rule, true)
	}

	delete(m.chains, c.Name)
}

func (m *mockFirewall) ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error) {
	var chains []*nftables.Chain
	for _, c := range globalFirewall.chains {
		if c.Chain.Table.Family == family {
			chains = append(chains, c.Chain)
		}
	}

	return chains, nil
}

func (m *mockFirewall) AddSet(s *nftables.Set, vals []nftables.SetElement) error {
	m.changed = true

	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	setName := s.Name
	if s.Anonymous {
		setName = fmt.Sprintf(anonSetName, setAllocNum)
		s.ID = uint32(setAllocNum)
		s.Name = anonSetName

		setAllocNum++
		t.newAnonSets[setName] = false
	}

	if _, ok := t.Sets[setName]; ok {
		// TODO: return error if set already exists?
		return nil
	}
	t.Sets[setName] = vals
	m.tables[s.Table.Name] = t

	return nil
}

func (m *mockFirewall) DelSet(s *nftables.Set) {
	m.changed = true

	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	delete(t.Sets, s.Name)
	m.tables[s.Table.Name] = t
}

func (m *mockFirewall) SetAddElements(s *nftables.Set, vals []nftables.SetElement) error {
	m.changed = true

	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	elements, ok := t.Sets[s.Name]
	if !ok {
		m.logger.Errorf("set %q not found", s.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	// don't add elements already present in set
	for _, val := range vals {
		if !slices.ContainsFunc(elements, func(e nftables.SetElement) bool {
			if !bytes.Equal(e.Key, val.Key) {
				return false
			}
			if !bytes.Equal(e.Val, val.Val) {
				return false
			}
			if !bytes.Equal(e.KeyEnd, val.KeyEnd) {
				return false
			}
			if e.IntervalEnd != val.IntervalEnd {
				return false
			}
			if (e.VerdictData != nil) != (val.VerdictData != nil) {
				return false
			}
			if e.VerdictData != nil {
				if e.VerdictData.Kind != val.VerdictData.Kind {
					return false
				}
				if e.VerdictData.Chain != val.VerdictData.Chain {
					return false
				}
			}
			if e.Timeout != val.Timeout {
				return false
			}
			return true
		}) {
			elements = append(elements, val)
		}
	}

	t.Sets[s.Name] = elements
	m.tables[s.Table.Name] = t

	return nil
}

func (m *mockFirewall) SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error {
	m.changed = true

	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	elements, ok := t.Sets[s.Name]
	if !ok {
		m.logger.Errorf("set %q not found", s.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	for _, v := range vals {
		i := slices.IndexFunc(elements, func(e nftables.SetElement) bool {
			if !bytes.Equal(e.Key, v.Key) {
				return false
			}
			if !bytes.Equal(e.KeyEnd, v.KeyEnd) {
				return false
			}
			if !bytes.Equal(e.Val, v.Val) {
				return false
			}
			return e.IntervalEnd == v.IntervalEnd
		})
		if i == -1 {
			m.logger.Errorf("set element with key %v not found", v.Key)
			m.flushErr = syscall.ENOENT
			continue
		}
		elements = slices.Delete(elements, i, i+1)
	}
	t.Sets[s.Name] = elements
	m.tables[s.Table.Name] = t

	return nil
}

func (m *mockFirewall) AddRule(r *nftables.Rule) *nftables.Rule {
	m.changed = true

	t, ok := m.tables[r.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", r.Table.Name)
		m.flushErr = syscall.ENOENT
		return r
	}
	c, ok := m.chains[r.Chain.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return r
	}

	// copy this rule so if we update it after flush the caller's rule
	// won't be updated
	rCopy := clone(r)
	m.checkRule(rCopy, t)

	c.Rules = append(c.Rules, rCopy)
	m.chains[r.Chain.Name] = c

	return r
}

func (m *mockFirewall) DelRule(r *nftables.Rule) error {
	m.changed = true

	m.delRule(r, false)

	return nil
}

func (m *mockFirewall) delRule(r *nftables.Rule, softDel bool) {
	if _, ok := m.tables[r.Table.Name]; !ok {
		m.logger.Errorf("table %q not found", r.Table.Name)
		m.flushErr = syscall.ENOENT
		return
	}
	c, ok := m.chains[r.Chain.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	i := slices.IndexFunc(c.Rules, func(r2 *nftables.Rule) bool {
		return rulesEqual(m.logger.Desugar(), r, r2)
	})
	if i == -1 {
		m.logger.Error("rule not found")
		m.flushErr = syscall.ENOENT
		return
	}

	// delete any anonymous sets associated with this rule
	for _, ruleExpr := range c.Rules[i].Exprs {
		lookupExpr, ok := ruleExpr.(*expr.Lookup)
		if !ok || !strings.HasPrefix(lookupExpr.SetName, "__set") {
			continue
		}

		m.DelSet(&nftables.Set{
			Table: c.Rules[i].Table,
			Name:  lookupExpr.SetName,
		})
	}

	if !softDel {
		c.Rules = slices.Delete(c.Rules, i, i+1)
		m.chains[r.Chain.Name] = c
	}
}

func (m *mockFirewall) InsertRule(r *nftables.Rule) *nftables.Rule {
	m.changed = true

	t, ok := m.tables[r.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", r.Table.Name)
		m.flushErr = syscall.ENOENT
		return r
	}
	c, ok := m.chains[r.Chain.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return r
	}

	// copy this rule so if we update it after flush the caller's rule
	// won't be updated
	rCopy := clone(r)
	m.checkRule(rCopy, t)

	c.Rules = slices.Insert(c.Rules, 0, rCopy)
	m.chains[r.Chain.Name] = c

	return r
}

func (m *mockFirewall) checkRule(r *nftables.Rule, t *table) {
	for _, ruleExpr := range r.Exprs {
		lookup, ok := ruleExpr.(*expr.Lookup)
		if ok && lookup.SetName == anonSetName {
			if lookup.SetID == 0 {
				m.flushErr = syscall.EINVAL
				break
			}
			// mark this expression to be updated after flush
			m.unsetLookupExprs = append(m.unsetLookupExprs, lookup)

			setName := fmt.Sprintf(anonSetName, lookup.SetID)
			if _, ok := t.newAnonSets[setName]; ok {
				// mark this anonymous set as valid now that a rule has
				// been added that uses it
				t.newAnonSets[setName] = true
			}
		}
	}
}

func (m *mockFirewall) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	ch, ok := globalFirewall.chains[c.Name]
	if !ok {
		return nil, syscall.ENOENT
	}

	return clone(ch.Rules), nil
}

func (m *mockFirewall) Flush() error {
	defer func() {
		m.changed = false
		m.tables = clone(globalFirewall.tables)
		initTables(m)
		m.chains = clone(globalFirewall.chains)
		m.flushErr = nil
	}()

	if m.flushErr != nil {
		return m.flushErr
	}

	// update lookup expressions
	for _, lookupExpr := range m.unsetLookupExprs {
		lookupExpr.SetName = fmt.Sprintf(lookupExpr.SetName, lookupExpr.SetID)
		lookupExpr.SetID = 0
	}
	m.unsetLookupExprs = nil

	// delete unused anonymous sets
	for _, t := range m.tables {
		for newAnonSet, used := range t.newAnonSets {
			if !used {
				delete(t.Sets, newAnonSet)
			}
		}
	}

	// only propagate changes if there were changes made
	if m.changed {
		globalFirewall.tables = m.tables
		globalFirewall.chains = m.chains
	}

	return nil
}

func clone[T any](t T) T {
	//nolint: forcetypeassert
	return copystructure.Must(copystructure.Copy(t)).(T)
}
