package main

import (
	"encoding/base64"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"strconv"
)

type Config struct {
	Port                    int                      `yaml:"port,omitempty"`
	SocksPort               int                      `yaml:"socks-port,omitempty"`
	MixedPort               int                      `yaml:"mixed-port,omitempty"`
	RedirPort               int                      `yaml:"redir-port,omitempty"`
	TproxyPort              int                      `yaml:"tproxy-port,omitempty"`
	AllowLan                bool                     `yaml:"allow-lan"`
	BindAddress             string                   `yaml:"bind-address,omitempty"`
	Authentication          []string                 `yaml:"authentication,omitempty"`
	SkipAuthPrefixes        []string                 `yaml:"skip-auth-prefixes,omitempty"`
	LanAllowedIPs           []string                 `yaml:"lan-allowed-ips,omitempty"`
	LanDisallowedIPs        []string                 `yaml:"lan-disallowed-ips,omitempty"`
	FindProcessMode         string                   `yaml:"find-process-mode,omitempty"`
	Mode                    string                   `yaml:"mode"`
	GeoxURL                 *GeoxURL                 `yaml:"geox-url,omitempty"`
	GeoAutoUpdate           bool                     `yaml:"geo-auto-update,omitempty"`
	GeoUpdateInterval       int                      `yaml:"geo-update-interval,omitempty"`
	GeositeMatcher          string                   `yaml:"geosite-matcher,omitempty"`
	LogLevel                string                   `yaml:"log-level"`
	IPv6                    bool                     `yaml:"ipv6,omitempty"`
	TLS                     *TLSConfig               `yaml:"tls,omitempty"`
	ExternalController      string                   `yaml:"external-controller,omitempty"`
	ExternalControllerTLS   string                   `yaml:"external-controller-tls,omitempty"`
	Secret                  string                   `yaml:"secret,omitempty"`
	ExternalControllerCORS  *CORSConfig              `yaml:"external-controller-cors,omitempty"`
	ExternalControllerUnix  string                   `yaml:"external-controller-unix,omitempty"`
	ExternalControllerPipe  string                   `yaml:"external-controller-pipe,omitempty"`
	TCPConcurrent           bool                     `yaml:"tcp-concurrent,omitempty"`
	ExternalUI              string                   `yaml:"external-ui,omitempty"`
	ExternalUIName          string                   `yaml:"external-ui-name,omitempty"`
	ExternalUIURL           string                   `yaml:"external-ui-url,omitempty"`
	ExternalDohServer       string                   `yaml:"external-doh-server,omitempty"`
	InterfaceName           string                   `yaml:"interface-name,omitempty"`
	GlobalClientFingerprint string                   `yaml:"global-client-fingerprint,omitempty"`
	DisableKeepAlive        bool                     `yaml:"disable-keep-alive,omitempty"`
	KeepAliveIdle           int                      `yaml:"keep-alive-idle,omitempty"`
	KeepAliveInterval       int                      `yaml:"keep-alive-interval,omitempty"`
	RoutingMark             int                      `yaml:"routing-mark,omitempty"`
	Experimental            *Experimental            `yaml:"experimental,omitempty"`
	Hosts                   map[string]interface{}   `yaml:"hosts,omitempty"`
	Profile                 *Profile                 `yaml:"profile,omitempty"`
	Tun                     *TunConfig               `yaml:"tun,omitempty"`
	Sniffer                 *SnifferConfig           `yaml:"sniffer,omitempty"`
	Tunnels                 []Tunnel                 `yaml:"tunnels,omitempty"`
	DNS                     *DNSConfig               `yaml:"dns,omitempty"`
	Proxies                 []Proxy                  `yaml:"proxies,omitempty"`
	ProxyGroups             []ProxyGroup             `yaml:"proxy-groups,omitempty"`
	ProxyProviders          map[string]ProxyProvider `yaml:"proxy-providers,omitempty"`
	RuleProviders           map[string]RuleProvider  `yaml:"rule-providers,omitempty"`
	Rules                   []string                 `yaml:"rules,omitempty"`
	SubRules                map[string][]string      `yaml:"sub-rules,omitempty"`
	Listeners               []Listener               `yaml:"listeners,omitempty"`
	// 注意：配置文件末尾还有一些入口配置（如 ss-config, vmess-config, tuic-server 等），这里暂未包含
}

type GeoxURL struct {
	GeoIP   string `yaml:"geoip,omitempty"`
	Geosite string `yaml:"geosite,omitempty"`
	MMDB    string `yaml:"mmdb,omitempty"`
}

type TLSConfig struct {
	Certificate        string   `yaml:"certificate,omitempty"`
	PrivateKey         string   `yaml:"private-key,omitempty"`
	ECHKey             string   `yaml:"ech-key,omitempty"`
	CustomCertificates []string `yaml:"custom-certificates,omitempty"`
}

type CORSConfig struct {
	AllowOrigins        []string `yaml:"allow-origins,omitempty"`
	AllowPrivateNetwork bool     `yaml:"allow-private-network,omitempty"`
}

type Experimental struct {
	QuicGoDisableGSO bool `yaml:"quic-go-disable-gso,omitempty"`
}

type Profile struct {
	StoreSelected bool `yaml:"store-selected,omitempty"`
	StoreFakeIP   bool `yaml:"store-fake-ip,omitempty"`
}

type TunConfig struct {
	Enable                 bool     `yaml:"enable,omitempty"`
	Stack                  string   `yaml:"stack,omitempty"`
	Device                 string   `yaml:"device,omitempty"`
	DNSHijack              []string `yaml:"dns-hijack,omitempty"`
	AutoDetectInterface    bool     `yaml:"auto-detect-interface,omitempty"`
	AutoRoute              bool     `yaml:"auto-route,omitempty"`
	MTU                    int      `yaml:"mtu,omitempty"`
	GSO                    bool     `yaml:"gso,omitempty"`
	GsoMaxSize             int      `yaml:"gso-max-size,omitempty"`
	AutoRedirect           bool     `yaml:"auto-redirect,omitempty"`
	StrictRoute            bool     `yaml:"strict-route,omitempty"`
	RouteAddressSet        []string `yaml:"route-address-set,omitempty"`
	RouteExcludeAddressSet []string `yaml:"route-exclude-address-set,omitempty"`
	RouteAddress           []string `yaml:"route-address,omitempty"`
	Inet4RouteAddress      []string `yaml:"inet4-route-address,omitempty"`
	Inet6RouteAddress      []string `yaml:"inet6-route-address,omitempty"`
	EndpointIndependentNat bool     `yaml:"endpoint-independent-nat,omitempty"`
	IncludeInterface       []string `yaml:"include-interface,omitempty"`
	ExcludeInterface       []string `yaml:"exclude-interface,omitempty"`
	IncludeUID             []int    `yaml:"include-uid,omitempty"`
	IncludeUIDRange        []string `yaml:"include-uid-range,omitempty"`
	ExcludeUID             []int    `yaml:"exclude-uid,omitempty"`
	ExcludeUIDRange        []string `yaml:"exclude-uid-range,omitempty"`
	IncludeAndroidUser     []int    `yaml:"include-android-user,omitempty"`
	IncludePackage         []string `yaml:"include-package,omitempty"`
	ExcludePackage         []string `yaml:"exclude-package,omitempty"`
}

type SnifferConfig struct {
	Enable              bool                   `yaml:"enable,omitempty"`
	ForceDNSMapping     bool                   `yaml:"force-dns-mapping,omitempty"`
	ParsePureIP         bool                   `yaml:"parse-pure-ip,omitempty"`
	OverrideDestination bool                   `yaml:"override-destination,omitempty"`
	Sniff               map[string]SniffConfig `yaml:"sniff,omitempty"`
	ForceDomain         []string               `yaml:"force-domain,omitempty"`
	SkipSrcAddress      []string               `yaml:"skip-src-address,omitempty"`
	SkipDstAddress      []string               `yaml:"skip-dst-address,omitempty"`
	SkipDomain          []string               `yaml:"skip-domain,omitempty"`
	Sniffing            []string               `yaml:"sniffing,omitempty"`
	PortWhitelist       []string               `yaml:"port-whitelist,omitempty"`
}

type SniffConfig struct {
	Ports               []string `yaml:"ports,omitempty"`
	OverrideDestination bool     `yaml:"override-destination,omitempty"`
}

type Tunnel struct {
	Network []string `yaml:"network,omitempty"`
	Address string   `yaml:"address,omitempty"`
	Target  string   `yaml:"target,omitempty"`
	Proxy   string   `yaml:"proxy,omitempty"`
}

type DNSConfig struct {
	CacheAlgorithm               string                 `yaml:"cache-algorithm,omitempty"`
	Enable                       bool                   `yaml:"enable,omitempty"`
	PreferH3                     bool                   `yaml:"prefer-h3,omitempty"`
	Listen                       string                 `yaml:"listen,omitempty"`
	IPv6                         bool                   `yaml:"ipv6,omitempty"`
	IPv6Timeout                  int                    `yaml:"ipv6-timeout,omitempty"`
	DefaultNameserver            []string               `yaml:"default-nameserver,omitempty"`
	EnhancedMode                 string                 `yaml:"enhanced-mode,omitempty"`
	FakeIPRange                  string                 `yaml:"fake-ip-range,omitempty"`
	FakeIPFilter                 []string               `yaml:"fake-ip-filter,omitempty"`
	FakeIPFilterMode             string                 `yaml:"fake-ip-filter-mode,omitempty"`
	UseHosts                     bool                   `yaml:"use-hosts,omitempty"`
	RespectRules                 bool                   `yaml:"respect-rules,omitempty"`
	Nameserver                   []string               `yaml:"nameserver,omitempty"`
	Fallback                     []string               `yaml:"fallback,omitempty"`
	ProxyServerNameserver        []string               `yaml:"proxy-server-nameserver,omitempty"`
	DirectNameserver             []string               `yaml:"direct-nameserver,omitempty"`
	DirectNameserverFollowPolicy bool                   `yaml:"direct-nameserver-follow-policy,omitempty"`
	FallbackFilter               *FallbackFilter        `yaml:"fallback-filter,omitempty"`
	NameserverPolicy             map[string]interface{} `yaml:"nameserver-policy,omitempty"`
}

type FallbackFilter struct {
	GeoIP     bool     `yaml:"geoip,omitempty"`
	GeoIPCode string   `yaml:"geoip-code,omitempty"`
	Geosite   []string `yaml:"geosite,omitempty"`
	IPCIDR    []string `yaml:"ipcidr,omitempty"`
	Domain    []string `yaml:"domain,omitempty"`
}

// 由于代理类型非常多，这里只定义一个基础的 Proxy 结构，实际使用时可能需要根据类型进行扩展
type Proxy struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	TLS      bool   `yaml:"tls,omitempty"`
	UDP      bool   `yaml:"udp,omitempty"`
	// 其他字段根据类型不同而变化，这里使用一个通用的 map 来存储其他选项
	Options map[string]interface{} `yaml:",inline"`
}

type ProxyGroup struct {
	Name           string   `yaml:"name"`
	Type           string   `yaml:"type"`
	Proxies        []string `yaml:"proxies,omitempty"`
	Tolerance      int      `yaml:"tolerance,omitempty"`
	Lazy           bool     `yaml:"lazy,omitempty"`
	ExpectedStatus int      `yaml:"expected-status,omitempty"`
	URL            string   `yaml:"url,omitempty"`
	Interval       int      `yaml:"interval,omitempty"`
	Strategy       string   `yaml:"strategy,omitempty"`
	DisableUDP     bool     `yaml:"disable-udp,omitempty"`
	Filter         string   `yaml:"filter,omitempty"`
	Use            []string `yaml:"use,omitempty"`
}

type ProxyProvider struct {
	Type        string              `yaml:"type"`
	URL         string              `yaml:"url,omitempty"`
	Interval    int                 `yaml:"interval,omitempty"`
	Path        string              `yaml:"path,omitempty"`
	Proxy       string              `yaml:"proxy,omitempty"`
	SizeLimit   int64               `yaml:"size-limit,omitempty"`
	Header      map[string][]string `yaml:"header,omitempty"`
	HealthCheck *HealthCheck        `yaml:"health-check,omitempty"`
	Override    *Override           `yaml:"override,omitempty"`
	DialerProxy string              `yaml:"dialer-proxy,omitempty"`
	Payload     []Proxy             `yaml:"payload,omitempty"`
}

type HealthCheck struct {
	Enable         bool   `yaml:"enable,omitempty"`
	Interval       int    `yaml:"interval,omitempty"`
	Lazy           bool   `yaml:"lazy,omitempty"`
	URL            string `yaml:"url,omitempty"`
	ExpectedStatus int    `yaml:"expected-status,omitempty"`
}

type Override struct {
	SkipCertVerify   bool               `yaml:"skip-cert-verify,omitempty"`
	UDP              bool               `yaml:"udp,omitempty"`
	Down             string             `yaml:"down,omitempty"`
	Up               string             `yaml:"up,omitempty"`
	DialerProxy      string             `yaml:"dialer-proxy,omitempty"`
	InterfaceName    string             `yaml:"interface-name,omitempty"`
	RoutingMark      int                `yaml:"routing-mark,omitempty"`
	IPVersion        string             `yaml:"ip-version,omitempty"`
	AdditionalPrefix string             `yaml:"additional-prefix,omitempty"`
	AdditionalSuffix string             `yaml:"additional-suffix,omitempty"`
	ProxyName        []ProxyNamePattern `yaml:"proxy-name,omitempty"`
}

type ProxyNamePattern struct {
	Pattern string `yaml:"pattern"`
	Target  string `yaml:"target"`
}

type RuleProvider struct {
	Behavior  string   `yaml:"behavior"`
	Interval  int      `yaml:"interval,omitempty"`
	Path      string   `yaml:"path,omitempty"`
	Type      string   `yaml:"type"`
	URL       string   `yaml:"url,omitempty"`
	Proxy     string   `yaml:"proxy,omitempty"`
	SizeLimit int64    `yaml:"size-limit,omitempty"`
	Format    string   `yaml:"format,omitempty"`
	Payload   []string `yaml:"payload,omitempty"`
}

type Listener struct {
	Name        string      `yaml:"name"`
	Type        string      `yaml:"type"`
	Port        interface{} `yaml:"port"` // 可以是 int 或 string（如 "200,302"）
	Listen      string      `yaml:"listen,omitempty"`
	Rule        string      `yaml:"rule,omitempty"`
	Proxy       string      `yaml:"proxy,omitempty"`
	UDP         bool        `yaml:"udp,omitempty"`
	Users       []User      `yaml:"users,omitempty"`
	Certificate string      `yaml:"certificate,omitempty"`
	PrivateKey  string      `yaml:"private-key,omitempty"`
	ECHKey      string      `yaml:"ech-key,omitempty"`
	// 其他类型特定的字段
	Password  string           `yaml:"password,omitempty"`
	Cipher    string           `yaml:"cipher,omitempty"`
	ShadowTLS *ShadowTLSConfig `yaml:"shadow-tls,omitempty"`
	// ... 其他字段根据类型不同而变化
}

type User struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	UUID     string `yaml:"uuid,omitempty"`
	AlterID  int    `yaml:"alterId,omitempty"`
}

type ShadowTLSConfig struct {
	Enable    bool   `yaml:"enable,omitempty"`
	Version   int    `yaml:"version,omitempty"`
	Password  string `yaml:"password,omitempty"`
	Users     []User `yaml:"users,omitempty"`
	Handshake string `yaml:"handshake,omitempty"`
}

// parseConfig reads, modifies, and encodes the application configuration.
// It returns the base64 encoded config string, the determined proxy address, and an error.
func parseConfig(isTun bool, configPath string) (string, string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read config file: %w", err)
	}

	var tempCfg Config
	if err := yaml.Unmarshal(data, &tempCfg); err != nil {
		return "", "", fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Determine proxy port
	var proxyPort int
	if tempCfg.Port != 0 {
		proxyPort = tempCfg.Port
	} else if tempCfg.MixedPort != 0 {
		proxyPort = tempCfg.MixedPort
	} else {
		proxyPort = 11111 // Default port
		tempCfg.MixedPort = proxyPort
	}
	newProxyAddr := "127.0.0.1:" + strconv.Itoa(proxyPort)

	// Enable or disable TUN mode based on the flag
	if isTun {
		if tempCfg.Tun != nil && tempCfg.DNS != nil {
			tempCfg.Tun.Enable = true
		} else {
			return "", "", fmt.Errorf("TUN mode selected but 'tun' or 'dns' section is missing in config.yaml")
		}
	} else {
		if tempCfg.Tun != nil {
			tempCfg.Tun.Enable = false
		}
	}

	// Marshal the modified config back to YAML
	configBytes, err := yaml.Marshal(&tempCfg)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// Return the base64 encoded string and the proxy address
	return base64.StdEncoding.EncodeToString(configBytes), newProxyAddr, nil
}
