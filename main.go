package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
)

type DnsHeader struct {
	Id      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

const (
	PACKAGE_MAX = 64 * 1024
)

func buildAnswer(id uint16, domain string, ip string) ([]byte, error) {
	var dnsHeader DnsHeader
	dnsHeader.Id = id
	dnsHeader.Flags = 0x8180
	dnsHeader.AnCount = 1
	dnsHeader.QdCount = 1
	dnsHeader.NsCount = 0
	dnsHeader.ArCount = 0

	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, dnsHeader)

	for _, namepart := range strings.Split(domain, ".") {
		buff.WriteByte(uint8(len(namepart)))
		buff.WriteString(namepart)
	}
	buff.WriteByte(0)
	binary.Write(buff, binary.BigEndian, uint32(0x00010001))
	buff.Write([]byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4})
	for _, ippart := range strings.Split(ip, ".") {
		b, err := strconv.ParseUint(ippart, 10, 8)
		if err != nil {
			log.Printf("ip format error: %s\n", err.Error())
			return nil, err
		}
		buff.WriteByte(byte(b))
	}
	return buff.Bytes(), nil
}

func parseQuery(data []byte) (uint16, string, error) {
	buff := bytes.NewBuffer(data)
	var dnsHeader DnsHeader
	err := binary.Read(buff, binary.BigEndian, &dnsHeader)
	if err != nil {
		log.Println("Data Error: %s\n", err.Error())
		return 0, "", errors.New("data_error")
	}
	log.Println(dnsHeader, len(data))

	domain := new(bytes.Buffer)
	for {
		var length uint8
		err = binary.Read(buff, binary.BigEndian, &length)
		if err != nil {
			log.Println("Data Error: %s\n", err.Error())
			return 0, "", errors.New("data_error")
		}
		if length == 0 {
			break
		}
		if domain.Len() != 0 {
			domain.WriteByte('.')
		}
		namepart := make([]byte, length)
		n, err := buff.Read(namepart)
		if err != nil {
			log.Println("Data Error: %s\n", err.Error())
			return 0, "", errors.New("data_error")
		}
		if n != int(length) {
			log.Println("Data Error: eof\n")
			return 0, "", errors.New("data_error")
		}
		domain.Write(namepart)
	}
	log.Println(domain.String())
	return dnsHeader.Id, domain.String(), nil
}

func main() {
	log.Println("start")
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	if err != nil {
		panic(err)
	}
	ln, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	for {
		data := make([]byte, PACKAGE_MAX)
		count, peer, err := ln.ReadFromUDP(data)
		if err != nil {
			log.Printf("Read Error: %s\n", err.Error())
			continue
		}
		if count < 12 {
			log.Println("Package Too Short: %v\n", count)
			continue
		}
		data = data[:count]
		id, domain, err := parseQuery(data)

		b, err := buildAnswer(id, domain, "1.2.3.4")
		if err != nil {
			log.Println("buildAnswer Error: %s\n", err.Error())
			continue
		}
		ln.WriteToUDP(b, peer)
	}
}
