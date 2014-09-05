package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
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

var (
	httpClient = &http.Client{}
	exp        = regexp.MustCompile(`<span class=t2>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</span>`)
	listen     = flag.String("listen", "127.0.0.1:53", "dns监听地址，格式为 ip:port")
)

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
	buff.Write([]byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04})
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
		log.Println("Read failed:", err)
		return 0, "", err
	}
	if dnsHeader.QdCount != 1 {
		log.Println("multiquery")
		return 0, "", nil
	}

	domain := new(bytes.Buffer)
	for {
		var length uint8
		err = binary.Read(buff, binary.BigEndian, &length)
		if err != nil {
			log.Println("Read failed:", err)
			return 0, "", err
		}
		if length == 0 {
			break
		}
		if domain.Len() != 0 {
			domain.WriteByte('.')
		}
		namepart := make([]byte, length)
		_, err = io.ReadFull(buff, namepart)
		if err != nil {
			log.Println("Read failed:", err)
			return 0, "", err
		}
		domain.Write(namepart)
	}
	var qtype struct {
		Type  uint16
		Class uint16
	}
	err = binary.Read(buff, binary.BigEndian, &qtype)
	if err != nil {
		log.Println("Read failed:", err)
		return 0, "", err
	}
	if qtype.Type != 1 || qtype.Class != 1 {
		log.Println("unknowtype", qtype)
		return 0, "", nil
	}

	return dnsHeader.Id, domain.String(), nil
}

func bindUDP(udpaddr string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", udpaddr)
	if err != nil {
		log.Println("ResolveUDPAddr failed:", err)
		return nil, err
	}
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Println("ListenUDP failed:", err)
		return nil, err
	}
	return sock, nil
}

func recvData(sock *net.UDPConn) ([]byte, *net.UDPAddr, error) {
	data := make([]byte, PACKAGE_MAX)
	count, peer, err := sock.ReadFromUDP(data)
	if err != nil {
		log.Println("ReadFormUDP failed:", err)
		return nil, nil, err
	}
	return data[:count], peer, nil
}

func proxyQuery(data []byte, serv *net.UDPConn, client *net.UDPAddr) {
	sock, err := bindUDP("0.0.0.0:0")
	if err != nil {
		log.Println("bindUDP failed:", err)
		return
	}
	defer sock.Close()
	realaddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}
	_, err = sock.WriteToUDP(data, realaddr)
	if err != nil {
		log.Println("WriteToUDP:", err)
		return
	}
	data = make([]byte, PACKAGE_MAX)
	count, _, err := sock.ReadFromUDP(data)
	if err != nil {
		log.Println("Read Error:", err)
		return
	}
	serv.WriteToUDP(data[:count], client)
}

func queryWeb(domain string) (string, error) {
	resp, err := httpClient.PostForm("http://ping.eu/action.php?atype=3", url.Values{"host": []string{domain}})
	if err != nil {
		log.Println("PostForm failed:", err)
		return "", err
	}
	defer resp.Body.Close()
	r, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("ReadAll failed:", err)
		return "", err
	}
	for _, result := range exp.FindAllSubmatch(r, -1) {
		ip := string(result[1])
		if ip != "127.0.0.1" {
			return ip, err
		}
	}
	return "", nil
}

func main() {
	log.Println("start")
	sock, err := bindUDP("10.15.44.83:53")
	if err != nil {
		log.Println("bindUDP failed:", err)
		return
	}
	defer sock.Close()
	for {
		data, peer, err := recvData(sock)
		go proxyQuery(data, sock, peer)
		continue
		log.Println("recv query")
		id, domain, err := parseQuery(data)
		if err != nil {
			log.Println("parseQuery failed:", err)
			continue
		}
		if domain == "" {
			log.Println("proxyQuery")
		} else {
			log.Println("queryWeb:", domain)
			ip, err := queryWeb(domain)
			if err != nil {
				log.Println("queryWeb failed:", err)
				go proxyQuery(data, sock, peer)
			} else if ip == "" {
				log.Println("queryWeb failed: not found")
				go proxyQuery(data, sock, peer)
			} else {
				log.Println("queryWeb get", ip)
				data, err := buildAnswer(id, domain, ip)
				if err != nil {
					log.Println("buildAnswer failed:", err)
					continue
				}
				n, err := sock.WriteToUDP(data, peer)
				if err != nil {
					log.Println("WriteToUDP failed:", err)
					continue
				}
				if n != len(data) {
					log.Println("WriteToUD failed: buffer full")
					continue
				}
			}
		}
	}
}
