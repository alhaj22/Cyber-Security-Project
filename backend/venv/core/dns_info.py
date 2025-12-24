"""
PhishRadar DNS Info - DNS and IP reputation analysis
Performs DNS lookups and ASN reputation checks
"""

import socket
import dns.resolver
from typing import Dict, List, Optional
from ipwhois import IPWhois
from .utils import logger, timing_decorator, safe_execute, data_manager

class DNSInfo:
    """DNS and IP address analysis"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
        self.cache = {}
        self.asn_reputation = self._load_asn_reputation()
        logger.info("DNSInfo initialized")
    
    def _load_asn_reputation(self) -> Dict:
        """Load ASN reputation data"""
        data = data_manager.load_json('reputation_asn.json')
        
        # Default known bad ASNs
        if not data:
            data = {
                'suspicious': [
                    {'asn': 'AS24940', 'name': 'Hetzner', 'risk': 40},
                    {'asn': 'AS14061', 'name': 'DigitalOcean', 'risk': 35},
                    {'asn': 'AS16276', 'name': 'OVH', 'risk': 35}
                ],
                'clean': [
                    {'asn': 'AS15169', 'name': 'Google', 'risk': 5},
                    {'asn': 'AS8075', 'name': 'Microsoft', 'risk': 5},
                    {'asn': 'AS16509', 'name': 'Amazon AWS', 'risk': 10}
                ]
            }
        
        return data
    
    @timing_decorator
    def lookup(self, domain: str) -> Dict:
        """
        Comprehensive DNS and IP analysis
        """
        if domain in self.cache:
            logger.debug(f"Using cached DNS data for {domain}")
            return self.cache[domain]
        
        try:
            logger.info(f"Performing DNS lookup for {domain}")
            
            # Resolve A records (IPv4)
            ipv4_addresses = self._resolve_a_records(domain)
            
            # Resolve AAAA records (IPv6)
            ipv6_addresses = self._resolve_aaaa_records(domain)
            
            # Resolve MX records
            mx_records = self._resolve_mx_records(domain)
            
            # Resolve NS records
            ns_records = self._resolve_ns_records(domain)
            
            # Get IP geolocation and ASN info (for first IPv4)
            ip_info = None
            asn_info = None
            if ipv4_addresses:
                ip_info = self._get_ip_geolocation(ipv4_addresses[0])
                asn_info = self._get_asn_info(ipv4_addresses[0])
            
            # Assess DNS risk
            risk_indicators = self._assess_dns_risk(
                ipv4_addresses, mx_records, ns_records, asn_info
            )
            
            result = {
                'domain': domain,
                'success': True,
                'ipv4_addresses': ipv4_addresses,
                'ipv6_addresses': ipv6_addresses,
                'ip_count': len(ipv4_addresses) + len(ipv6_addresses),
                'mx_records': mx_records,
                'mx_count': len(mx_records),
                'ns_records': ns_records,
                'ns_count': len(ns_records),
                'ip_info': ip_info,
                'asn_info': asn_info,
                'risk_indicators': risk_indicators,
                'risk_score': self._calculate_dns_risk_score(risk_indicators)
            }
            
            # Cache result
            self.cache[domain] = result
            
            logger.debug(f"DNS lookup complete for {domain}")
            return result
            
        except Exception as e:
            logger.error(f"DNS lookup failed for {domain}: {e}")
            return self._error_result(domain, str(e))
    
    @safe_execute(default_return=[])
    def _resolve_a_records(self, domain: str) -> List[str]:
        """Resolve A records (IPv4)"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain not found: {domain}")
            return []
        except dns.resolver.NoAnswer:
            logger.debug(f"No A records for {domain}")
            return []
        except Exception as e:
            logger.debug(f"A record lookup failed for {domain}: {e}")
            return []
    
    @safe_execute(default_return=[])
    def _resolve_aaaa_records(self, domain: str) -> List[str]:
        """Resolve AAAA records (IPv6)"""
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(rdata) for rdata in answers]
        except:
            return []
    
    @safe_execute(default_return=[])
    def _resolve_mx_records(self, domain: str) -> List[Dict]:
        """Resolve MX records"""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [
                {'priority': rdata.preference, 'exchange': str(rdata.exchange)}
                for rdata in answers
            ]
        except:
            return []
    
    @safe_execute(default_return=[])
    def _resolve_ns_records(self, domain: str) -> List[str]:
        """Resolve NS records"""
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in answers]
        except:
            return []
    
    @safe_execute(default_return=None)
    def _get_ip_geolocation(self, ip: str) -> Optional[Dict]:
        """Get IP geolocation using socket"""
        try:
            # Simple hostname lookup
            hostname = socket.gethostbyaddr(ip)
            return {
                'ip': ip,
                'hostname': hostname[0] if hostname else None,
                'reverse_dns': hostname[0] if hostname else None
            }
        except:
            return {'ip': ip, 'hostname': None, 'reverse_dns': None}
    
    @safe_execute(default_return=None)
    def _get_asn_info(self, ip: str) -> Optional[Dict]:
        """Get ASN information for IP"""
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            
            asn = results.get('asn')
            asn_description = results.get('asn_description')
            asn_country = results.get('asn_country_code')
            
            # Check reputation
            reputation = self._check_asn_reputation(asn)
            
            return {
                'asn': asn,
                'asn_description': asn_description,
                'asn_country': asn_country,
                'reputation': reputation,
                'network': results.get('network', {})
            }
        except Exception as e:
            logger.debug(f"ASN lookup failed for {ip}: {e}")
            return None
    
    def _check_asn_reputation(self, asn: str) -> Dict:
        """Check ASN against reputation database"""
        if not asn:
            return {'status': 'unknown', 'risk': 50}
        
        # Check suspicious list
        for entry in self.asn_reputation.get('suspicious', []):
            if entry['asn'] == asn:
                return {
                    'status': 'suspicious',
                    'risk': entry['risk'],
                    'name': entry['name']
                }
        
        # Check clean list
        for entry in self.asn_reputation.get('clean', []):
            if entry['asn'] == asn:
                return {
                    'status': 'clean',
                    'risk': entry['risk'],
                    'name': entry['name']
                }
        
        return {'status': 'unknown', 'risk': 30}
    
    def _assess_dns_risk(
        self,
        ipv4_addresses: List[str],
        mx_records: List[Dict],
        ns_records: List[str],
        asn_info: Optional[Dict]
    ) -> Dict[str, bool]:
        """Assess DNS-based risk indicators"""
        
        indicators = {
            'no_ip_address': len(ipv4_addresses) == 0,
            'no_mx_records': len(mx_records) == 0,
            'no_ns_records': len(ns_records) == 0,
            'single_ip': len(ipv4_addresses) == 1,
            'many_ips': len(ipv4_addresses) > 10,
            'few_ns_records': 0 < len(ns_records) < 2,
            'suspicious_asn': (
                asn_info is not None and 
                asn_info.get('reputation', {}).get('status') == 'suspicious'
            ),
            'high_risk_hosting': (
                asn_info is not None and
                asn_info.get('reputation', {}).get('risk', 0) > 50
            )
        }
        
        return indicators
    
    def _calculate_dns_risk_score(self, indicators: Dict[str, bool]) -> float:
        """Calculate DNS risk score (0-100)"""
        weights = {
            'no_ip_address': 40,
            'no_mx_records': 10,
            'no_ns_records': 15,
            'single_ip': 5,
            'many_ips': 10,
            'few_ns_records': 10,
            'suspicious_asn': 30,
            'high_risk_hosting': 25
        }
        
        score = sum(
            weights.get(indicator, 0)
            for indicator, present in indicators.items()
            if present
        )
        
        return min(score, 100)
    
    def _error_result(self, domain: str, error: str) -> Dict:
        """Return error result structure"""
        return {
            'domain': domain,
            'success': False,
            'error': error,
            'ipv4_addresses': [],
            'risk_indicators': {'dns_failure': True},
            'risk_score': 60  # Medium-high risk when DNS fails
        }
    
    def batch_lookup(self, domains: List[str]) -> Dict[str, Dict]:
        """Perform DNS lookup on multiple domains"""
        results = {}
        for domain in domains:
            results[domain] = self.lookup(domain)
        return results
    
    def clear_cache(self):
        """Clear DNS cache"""
        self.cache.clear()
        logger.info("DNS cache cleared")