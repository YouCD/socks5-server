package ldapAuth

import (
	"errors"
	"github.com/go-ldap/ldap"

	"sync"
	"time"
)

var (
	ErrInvalidConfig = errors.New("invalid pool config")
	ErrPoolClosed    = errors.New("pool closed")
	LdapPool         Pool
)

func InitDefaultpPool(host string) (err error) {
	LdapPool, err = NewDefaultPool(host)
	if err != nil {
		return err
	}
	return
}

type factory func() (*ldap.Conn, error)

type Pool interface {
	Acquire(user string, password string) (*ldap.Conn, error) // 获取资源
	Release(*ldap.Conn)                                       // 释放资源
	Close(*ldap.Conn) error                                   // 关闭资源
	Shutdown() error                                          // 关闭池
}

type GenericPool struct {
	sync.Mutex
	pool        chan *ldap.Conn
	maxOpen     int  // 池中最大资源数
	numOpen     int  // 当前池中资源数
	minOpen     int  // 池中最少资源数
	closed      bool // 池是否已关闭
	maxLifetime time.Duration
	factory     factory // 创建连接的方法
}

func NewGenericPool(minOpen, maxOpen int, maxLifetime time.Duration, factory factory) (*GenericPool, error) {
	if maxOpen <= 0 || minOpen > maxOpen {
		return nil, ErrInvalidConfig
	}
	p := &GenericPool{
		maxOpen:     maxOpen,
		minOpen:     minOpen,
		maxLifetime: maxLifetime,
		factory:     factory,
		pool:        make(chan *ldap.Conn, maxOpen),
	}
	for i := 0; i < minOpen; i++ {
		closer, err := factory()
		if err != nil {
			return nil, err
		}
		p.numOpen++
		p.pool <- closer
	}
	return p, nil
}
func NewDefaultPool(host string) (*GenericPool, error) {
	return NewGenericPool(5, 15, time.Second*60, func() (l *ldap.Conn, e error) {

		l, e = ldap.Dial("tcp", host)
		if e != nil {
			return
		}
		return
	})
}
func (p *GenericPool) Acquire(user, password string) (*ldap.Conn, error) {
	if p.closed {
		return nil, ErrPoolClosed
	}
	for i := 0; i < p.maxOpen+10; i++ {
		closer, err := p.getOrCreate()
		if err != nil {
			return nil, err
		}

		e := closer.Bind(user, password)
		if e != nil {
			continue
		}

		return closer, nil
	}
	return nil, ErrPoolClosed
}

func (p *GenericPool) getOrCreate() (*ldap.Conn, error) {

	p.Lock()
	defer p.Unlock()
	select {
	case closer := <-p.pool:
		p.numOpen--
		return closer, nil
	default:
	}
	if p.numOpen >= p.maxOpen {
		closer := <-p.pool
		return closer, nil
	}
	// 新建连接
	closer, err := p.factory()
	if err != nil {
		return nil, err
	}
	return closer, nil
}

// Release 释放单个资源到连接池
func (p *GenericPool) Release(closer *ldap.Conn) {
	if p.closed {
		return
	}
	p.Lock()
	defer p.Unlock()
	if p.numOpen < p.maxOpen {
		p.pool <- closer
		p.numOpen++
		return
	}
	closer.Close()
	return
}

// Close 关闭单个资源
func (p *GenericPool) Close(closer *ldap.Conn) error {
	p.Lock()
	defer p.Unlock()
	closer.Close()
	p.numOpen--
	return nil
}

// Shutdown 关闭连接池，释放所有资源
func (p *GenericPool) Shutdown() error {
	if p.closed {
		return ErrPoolClosed
	}
	p.Lock()
	defer p.Unlock()
	close(p.pool)
	for closer := range p.pool {
		closer.Close()
		p.numOpen--
	}
	p.closed = true
	return nil
}
