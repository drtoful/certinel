package certinel

import (
	"bytes"
	"errors"

	"github.com/boltdb/bolt"
)

const (
	fileMode = 0600
)

var (
	_store *Store = nil

	ErrNoBucket      = errors.New("no bucket given")
	ErrInvalidBucket = errors.New("no bucket found with given name")
)

// Store provides a structured way to load data from an underlying database
// (i.e. key-value store)
type Store struct {
	db   *bolt.DB
	path string
}

// KeyValue represents a key-value pair from the underlying key-value store
type KeyValue struct {
	Key   string
	Value string
}

// create a new Store and initialize it
func StoreInit(path string) error {
	// open the BoltDB and return error if this did not work
	// (beware that the same DB can only be opened by one
	// process)
	handle, err := bolt.Open(path, fileMode, nil)
	if err != nil {
		return err
	}

	// create the store
	_store = &Store{
		db:   handle,
		path: path,
	}

	return nil
}

func GetStore() *Store {
	return _store
}

// close all connections to the underlying database file to be used
// by another process
func (store *Store) Close() {
	store.db.Close()
}

func (store *Store) resolveBucket(tx *bolt.Tx, bucket []string) (*bolt.Bucket, error) {
	if len(bucket) == 0 {
		return nil, ErrNoBucket
	}

	b := tx.Bucket([]byte(bucket[0]))
	if b == nil {
		return nil, ErrInvalidBucket
	}

	for i := 1; i < len(bucket); i += 1 {
		b = b.Bucket([]byte(bucket[1]))
		if b == nil {
			return nil, ErrInvalidBucket
		}
	}

	return b, nil
}

// set a key to the specified value. you need also to specify the bucket
// you want to write this key-value pair into.
func (store *Store) Set(bucket []string, key, value string) error {
	err := store.db.Update(func(tx *bolt.Tx) error {
		b, err := store.resolveBucket(tx, bucket)
		if err != nil {
			return err
		}

		err = b.Put([]byte(key), []byte(value))
		return err
	})

	return err
}

// get the content of a key from the specified bucket
func (store *Store) Get(bucket []string, key string) (value string, err error) {
	err = store.db.View(func(tx *bolt.Tx) error {
		b, err := store.resolveBucket(tx, bucket)
		if err != nil {
			return err
		}

		value = string(b.Get([]byte(key)))

		return nil
	})

	return value, err
}

// create a new bucket
func (store *Store) Create(bucket []byte) (err error) {
	err = store.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucket)
		return err
	})

	return err
}

// delete a bucket
func (store *Store) Remove(bucket string) (err error) {
	err = store.db.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(bucket))
		return err
	})

	return err
}

// check if a bucket exists
func (store *Store) BucketExists(bucket []string) bool {
	err := store.db.View(func(tx *bolt.Tx) error {
		_, err := store.resolveBucket(tx, bucket)
		return err
	})
	return err == nil
}

// get a list of all buckets, starting with a given prefix
func (store *Store) Buckets(prefix string) (<-chan *KeyValue, error) {
	channel := make(chan *KeyValue)
	go func() {
		list := make([]*KeyValue, 0)
		n := 0

		_ = store.db.View(func(tx *bolt.Tx) error {
			_prefix := []byte(prefix)
			tx.ForEach(func(name []byte, b *bolt.Bucket) error {
				if bytes.HasPrefix(name, _prefix) {
					list = append(list, &KeyValue{Key: "Bucket", Value: string(name)})
					n = n + 1
				}

				return nil
			})

			return nil
		})

		for i := 0; i < n; i += 1 {
			channel <- list[i]
		}
		close(channel)
	}()

	return channel, nil
}

// get the content of a key that acts as a prefix from the specified bucket. this func
// will return immediately and return a channel from which you can get a KeyValue object.
// if the end is reached, the channel will return nil.
// Note that this method does not return an error it will just immediately put nil into
// the channel if something happened.
func (store *Store) Scan(bucket []string, prefix string, reverse bool) <-chan *KeyValue {
	channel := make(chan *KeyValue)
	go func() {
		list := make([]*KeyValue, 0)
		n := 0

		_ = store.db.View(func(tx *bolt.Tx) error {
			b, err := store.resolveBucket(tx, bucket)
			if err != nil {
				return err
			}

			prefix_ := []byte(prefix)
			if reverse {
				prefix_ = []byte(prefix + "~")
			}
			c := b.Cursor()
			for k, v := c.Seek(prefix_); bytes.HasPrefix(k, prefix_); {
				list = append(list, &KeyValue{Key: string(k), Value: string(v)})
				n = n + 1

				if reverse {
					prefix_ = []byte(prefix)
					k, v = c.Prev()
				} else {
					k, v = c.Next()
				}
			}

			return nil
		})

		for i := 0; i < n; i += 1 {
			channel <- list[i]
		}
		close(channel)
	}()

	return channel
}

// delete a key from the specified bucket
func (store *Store) Delete(bucket []string, key string) error {
	err := store.db.Update(func(tx *bolt.Tx) error {
		b, err := store.resolveBucket(tx, bucket)
		if err != nil {
			return err
		}

		err = b.Delete([]byte(key))
		return err
	})

	return err
}
