package vptable

import (
	"github.com/colinmarc/cdb"
)

// VPTable contains a complete password database for VMailMgr including
// the right order to ensure the database does not change if there are
// no content changes
type VPTable struct {
	order   []string
	entries map[string]*VPEntry
}

// Get retrieves a pointer to the VPEntry of the user given as key
func (v VPTable) Get(key string) *VPEntry {
	if entry, ok := v.entries[key]; ok {
		return entry
	}

	return nil
}

// LoadFromFile reads the CDB file and parses the entries to be editable
func LoadFromFile(srcFile string) (*VPTable, error) {
	db, err := cdb.Open(srcFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	vpt := &VPTable{
		order:   []string{},
		entries: map[string]*VPEntry{},
	}

	it := db.Iter()
	for it.Next() {
		vpt.order = append(vpt.order, string(it.Key()))
		vpt.entries[string(it.Key())] = parseVpentry(it.Value())
	}

	return vpt, nil
}

func New() *VPTable {
	return &VPTable{
		order:   []string{},
		entries: map[string]*VPEntry{},
	}
}

func (v *VPTable) Remove(key string) {
	delete(v.entries, key)
	for i, e := range v.order {
		if e == key {
			v.order = append(v.order[:i], v.order[i+1:]...)
		}
	}
}

// SaveToFile writes the database into the CDB file format
func (v VPTable) SaveToFile(destFile string) error {
	w, err := cdb.Create(destFile)
	if err != nil {
		return err
	}
	defer w.Close()

	for _, key := range v.order {
		w.Put([]byte(key), v.entries[key].encode())
	}

	return nil
}

// Upsert adds a new entry if it does not exist or updates the existing
// if it already does (not required when using Get as the pointer can be
// changed directly)
func (v *VPTable) Upsert(key string, entry *VPEntry) {
	if _, ok := v.entries[key]; !ok {
		v.order = append(v.order, key)
	}

	v.entries[key] = entry
}

// Users returns a list of all known users
func (v VPTable) Users() []string {
	return v.order
}
