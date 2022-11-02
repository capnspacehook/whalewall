package main

import (
	"bytes"
	"syscall"

	"github.com/google/nftables"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
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

	tables map[string]table
	chains map[string]chain

	flushErr error
}

type table struct {
	sets setMap
}

type chain struct {
	chain *nftables.Chain
	rules []*nftables.Rule
}

type setMap map[string][]nftables.SetElement

func newMockFirewall(logger *zap.Logger) *mockFirewall {
	return &mockFirewall{
		logger: logger.Sugar(),
		tables: make(map[string]table),
		chains: make(map[string]chain),
	}
}

func (m *mockFirewall) AddTable(t *nftables.Table) *nftables.Table {
	if _, ok := m.tables[t.Name]; !ok {
		m.tables[t.Name] = table{
			sets: make(setMap),
		}
	}

	return t
}

func (m *mockFirewall) AddChain(c *nftables.Chain) *nftables.Chain {
	if _, ok := m.chains[c.Name]; !ok {
		m.chains[c.Name] = chain{
			chain: c,
		}
	}

	return c
}

func (m *mockFirewall) DelChain(c *nftables.Chain) {
	if _, ok := m.chains[c.Name]; !ok {
		m.logger.Errorf("chain %q not found", c.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	delete(m.chains, c.Name)
}

func (m *mockFirewall) ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error) {
	var chains []*nftables.Chain
	for _, c := range m.chains {
		if c.chain.Table.Family == family {
			chains = append(chains, c.chain)
		}
	}

	return chains, nil
}

func (m *mockFirewall) AddSet(s *nftables.Set, vals []nftables.SetElement) error {
	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	if _, ok := t.sets[s.Name]; ok {
		// TODO: return error if set already exists?
		return nil
	}
	t.sets[s.Name] = vals
	m.tables[s.Table.Name] = t

	return nil
}

func (m *mockFirewall) DelSet(s *nftables.Set) {
	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	delete(t.sets, s.Name)
	m.tables[s.Table.Name] = t
}

func (m *mockFirewall) SetAddElements(s *nftables.Set, vals []nftables.SetElement) error {
	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	elements, ok := t.sets[s.Name]
	if !ok {
		m.logger.Errorf("set %q not found", s.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}
	elements = append(elements, vals...)
	t.sets[s.Name] = elements
	m.tables[s.Table.Name] = t

	return nil
}

func (m *mockFirewall) SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error {
	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	elements, ok := t.sets[s.Name]
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
		}
		elements = slices.Delete(elements, i, i)
	}
	t.sets[s.Name] = elements
	m.tables[s.Table.Name] = t

	return nil
}

func (m *mockFirewall) AddRule(r *nftables.Rule) *nftables.Rule {
	c, ok := m.chains[r.Chain.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return r
	}

	c.rules = append(c.rules, r)
	m.chains[r.Chain.Name] = c

	return r
}

func (m *mockFirewall) DelRule(r *nftables.Rule) error {
	c, ok := m.chains[r.Chain.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	i := slices.IndexFunc(c.rules, func(r2 *nftables.Rule) bool {
		return rulesEqual(m.logger.Desugar(), r, r2)
	})
	if i == -1 {
		m.logger.Error("rule not found")
		m.flushErr = syscall.ENOENT
		return nil
	}

	c.rules = slices.Delete(c.rules, i, i)
	m.chains[r.Chain.Name] = c

	return nil
}

func (m *mockFirewall) InsertRule(r *nftables.Rule) *nftables.Rule {
	c, ok := m.chains[r.Chain.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return r
	}

	c.rules = slices.Insert(c.rules, 0, r)
	m.chains[r.Chain.Name] = c

	return r
}

func (m *mockFirewall) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	ch, ok := m.chains[c.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", c.Name)
		m.flushErr = syscall.ENOENT
		return nil, nil
	}

	return slices.Clone(ch.rules), nil
}

func (m *mockFirewall) Flush() error {
	return m.flushErr
}
