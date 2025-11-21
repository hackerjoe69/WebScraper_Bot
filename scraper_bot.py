import asyncio
import aiohttp
import requests
from bs4 import BeautifulSoup
import json
import re
import time
from urllib.parse import quote, urlencode, urlparse
import random
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import logging
import argparse
import sys
import os
import csv
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scraping_bot.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    """Print the advanced web scraping bot banner in green"""
    banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                ADVANCED WEB SCRAPING BOT                                     ║
║                                                                              ║
║    Multi-Search Engine Scraper • IP Intelligence Investigator                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def print_green(text):
    """Print text in green color"""
    print(f"{Colors.GREEN}{text}{Colors.END}")

def print_blue(text):
    """Print text in blue color"""
    print(f"{Colors.BLUE}{text}{Colors.END}")

def print_yellow(text):
    """Print text in yellow color"""
    print(f"{Colors.YELLOW}{text}{Colors.END}")

def print_red(text):
    """Print text in red color"""
    print(f"{Colors.RED}{text}{Colors.END}")

@dataclass
class SearchResult:
    """Data class to store search results"""
    source: str
    title: str
    url: str
    snippet: str
    keywords: List[str]
    timestamp: str

@dataclass
class IPInfo:
    """Data class to store IP address information"""
    ip: str
    country: str
    city: str
    region: str
    org: str
    postal: str
    timezone: str
    asn: str
    source: str
    timestamp: str

class RobotsTxtChecker:
    """Class to check robots.txt compliance"""
    
    def __init__(self, session):
        self.session = session
        self.robots_cache = {}
    
    async def check_robots_txt(self, base_url: str, user_agent: str = '*') -> Dict[str, Any]:
        """Check robots.txt for a given domain"""
        try:
            parsed_url = urlparse(base_url)
            domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
            robots_url = f"{domain}/robots.txt"
            
            # Check cache first
            cache_key = f"{domain}_{user_agent}"
            if cache_key in self.robots_cache:
                return self.robots_cache[cache_key]
            
            async with self.session.get(robots_url) as response:
                if response.status == 200:
                    robots_content = await response.text()
                    is_allowed = self.parse_robots_txt(robots_content, parsed_url.path, user_agent)
                    
                    result = {
                        'domain': domain,
                        'robots_url': robots_url,
                        'exists': True,
                        'allowed': is_allowed,
                        'crawl_delay': self.get_crawl_delay(robots_content, user_agent),
                        'user_agent': user_agent
                    }
                else:
                    result = {
                        'domain': domain,
                        'robots_url': robots_url,
                        'exists': False,
                        'allowed': True,  # Assume allowed if no robots.txt
                        'crawl_delay': None,
                        'user_agent': user_agent
                    }
            
            self.robots_cache[cache_key] = result
            return result
            
        except Exception as e:
            logging.error(f"Robots.txt check error for {base_url}: {e}")
            return {
                'domain': domain,
                'robots_url': robots_url,
                'exists': False,
                'allowed': True,
                'crawl_delay': None,
                'user_agent': user_agent,
                'error': str(e)
            }
    
    def parse_robots_txt(self, content: str, path: str, user_agent: str) -> bool:
        """Parse robots.txt content to check if path is allowed"""
        lines = content.split('\n')
        current_ua = None
        allowed = True
        
        for line in lines:
            line = line.strip()
            if line.lower().startswith('user-agent:'):
                current_ua = line.split(':', 1)[1].strip()
            elif line.lower().startswith('disallow:') and current_ua in [user_agent, '*']:
                disallow_path = line.split(':', 1)[1].strip()
                if disallow_path and path.startswith(disallow_path):
                    allowed = False
            elif line.lower().startswith('allow:') and current_ua in [user_agent, '*']:
                allow_path = line.split(':', 1)[1].strip()
                if allow_path and path.startswith(allow_path):
                    allowed = True
        
        return allowed
    
    def get_crawl_delay(self, content: str, user_agent: str) -> Optional[float]:
        """Extract crawl delay from robots.txt"""
        lines = content.split('\n')
        current_ua = None
        
        for line in lines:
            line = line.strip()
            if line.lower().startswith('user-agent:'):
                current_ua = line.split(':', 1)[1].strip()
            elif line.lower().startswith('crawl-delay:') and current_ua in [user_agent, '*']:
                try:
                    return float(line.split(':', 1)[1].strip())
                except ValueError:
                    continue
        return None


class AdvancedScrapingBot:
    def __init__(self):
        self.session = None
        self.robots_checker = None
        self.headers_list = [
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            },
            {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
        ]
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        self.robots_checker = RobotsTxtChecker(self.session)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def get_random_headers(self):
        return random.choice(self.headers_list)

    def is_ip_address(self, text: str) -> bool:
        """Check if the input is an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, text):
            return all(0 <= int(part) <= 255 for part in text.split('.'))
        return False

    async def check_and_respect_robots(self, url: str, user_agent: str = '*') -> bool:
        """Check robots.txt and respect crawl delays"""
        try:
            robots_info = await self.robots_checker.check_robots_txt(url, user_agent)
            
            if not robots_info['allowed']:
                print_yellow(f"⚠️  Robots.txt disallows crawling: {url}")
                return False
            
            if robots_info['crawl_delay']:
                print_yellow(f"⏳ Respecting crawl delay: {robots_info['crawl_delay']} seconds")
                await asyncio.sleep(robots_info['crawl_delay'])
            else:
                # Default delay to be respectful
                await asyncio.sleep(random.uniform(1, 3))
            
            return True
            
        except Exception as e:
            logging.error(f"Robots check error: {e}")
            # Be conservative - add delay even if check fails
            await asyncio.sleep(random.uniform(2, 4))
            return True

    async def search_google(self, query: str, num_results: int = 10) -> List[SearchResult]:
        """Search Google for the given query"""
        results = []
        try:
            url = f"https://www.google.com/search?q={quote(query)}&num={num_results}"
            
            # Check robots.txt
            if not await self.check_and_respect_robots(url, '*'):
                return results
                
            headers = self.get_random_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    for g in soup.find_all('div', class_='g'):
                        title_elem = g.find('h3')
                        link_elem = g.find('a')
                        snippet_elem = g.find('span', class_='aCOpRe')
                        
                        if title_elem and link_elem:
                            title = title_elem.get_text()
                            url = link_elem.get('href')
                            snippet = snippet_elem.get_text() if snippet_elem else ""
                            
                            if url and url.startswith('/url?q='):
                                url = url[7:].split('&')[0]
                                
                            results.append(SearchResult(
                                source="Google",
                                title=title,
                                url=url,
                                snippet=snippet,
                                keywords=query.split(),
                                timestamp=datetime.now().isoformat()
                            ))
                    
                    logging.info(f"Google search completed: {len(results)} results")
                    
        except Exception as e:
            logging.error(f"Google search error: {e}")
            
        return results

    async def search_duckduckgo(self, query: str, num_results: int = 10) -> List[SearchResult]:
        """Search DuckDuckGo for the given query"""
        results = []
        try:
            url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
            
            # Check robots.txt
            if not await self.check_and_respect_robots(url, '*'):
                return results
                
            headers = self.get_random_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    for result in soup.find_all('div', class_='result'):
                        title_elem = result.find('a', class_='result__a')
                        snippet_elem = result.find('a', class_='result__snippet')
                        
                        if title_elem:
                            title = title_elem.get_text()
                            url = title_elem.get('href')
                            snippet = snippet_elem.get_text() if snippet_elem else ""
                            
                            results.append(SearchResult(
                                source="DuckDuckGo",
                                title=title,
                                url=url,
                                snippet=snippet,
                                keywords=query.split(),
                                timestamp=datetime.now().isoformat()
                            ))
                    
                    logging.info(f"DuckDuckGo search completed: {len(results)} results")
                    
        except Exception as e:
            logging.error(f"DuckDuckGo search error: {e}")
            
        return results

    async def search_bing(self, query: str, num_results: int = 10) -> List[SearchResult]:
        """Search Bing for the given query"""
        results = []
        try:
            url = f"https://www.bing.com/search?q={quote(query)}&count={num_results}"
            
            # Check robots.txt
            if not await self.check_and_respect_robots(url, '*'):
                return results
                
            headers = self.get_random_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    for result in soup.find_all('li', class_='b_algo'):
                        title_elem = result.find('h2')
                        link_elem = result.find('a')
                        snippet_elem = result.find('p')
                        
                        if title_elem and link_elem:
                            title = title_elem.get_text()
                            url = link_elem.get('href')
                            snippet = snippet_elem.get_text() if snippet_elem else ""
                            
                            results.append(SearchResult(
                                source="Bing",
                                title=title,
                                url=url,
                                snippet=snippet,
                                keywords=query.split(),
                                timestamp=datetime.now().isoformat()
                            ))
                    
                    logging.info(f"Bing search completed: {len(results)} results")
                    
        except Exception as e:
            logging.error(f"Bing search error: {e}")
            
        return results

    async def search_yahoo(self, query: str, num_results: int = 10) -> List[SearchResult]:
        """Search Yahoo for the given query"""
        results = []
        try:
            url = f"https://search.yahoo.com/search?p={quote(query)}&n={num_results}"
            
            # Check robots.txt
            if not await self.check_and_respect_robots(url, '*'):
                return results
                
            headers = self.get_random_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Yahoo search results parsing
                    for result in soup.find_all('div', class_='algo'):
                        title_elem = result.find('h3')
                        link_elem = result.find('a')
                        snippet_elem = result.find('p')
                        
                        if title_elem and link_elem:
                            title = title_elem.get_text()
                            url = link_elem.get('href')
                            snippet = snippet_elem.get_text() if snippet_elem else ""
                            
                            results.append(SearchResult(
                                source="Yahoo",
                                title=title,
                                url=url,
                                snippet=snippet,
                                keywords=query.split(),
                                timestamp=datetime.now().isoformat()
                            ))
                    
                    logging.info(f"Yahoo search completed: {len(results)} results")
                    
        except Exception as e:
            logging.error(f"Yahoo search error: {e}")
            
        return results

    async def search_brave(self, query: str, num_results: int = 10) -> List[SearchResult]:
        """Search Brave for the given query"""
        results = []
        try:
            url = f"https://search.brave.com/search?q={quote(query)}"
            
            # Check robots.txt
            if not await self.check_and_respect_robots(url, '*'):
                return results
                
            headers = self.get_random_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Brave search results parsing
                    for result in soup.find_all('div', {'data-type': 'web'}):
                        title_elem = result.find('div', class_='title')
                        link_elem = result.find('a')
                        snippet_elem = result.find('div', class_='snippet')
                        
                        if title_elem and link_elem:
                            title = title_elem.get_text().strip()
                            url = link_elem.get('href')
                            snippet = snippet_elem.get_text() if snippet_elem else ""
                            
                            results.append(SearchResult(
                                source="Brave",
                                title=title,
                                url=url,
                                snippet=snippet,
                                keywords=query.split(),
                                timestamp=datetime.now().isoformat()
                            ))
                    
                    logging.info(f"Brave search completed: {len(results)} results")
                    
        except Exception as e:
            logging.error(f"Brave search error: {e}")
            
        return results

    async def get_ipinfo_data(self, ip: str) -> Optional[IPInfo]:
        """Get IP information from ipinfo.io"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            
            # Check robots.txt
            if not await self.check_and_respect_robots(url, '*'):
                return None
                
            headers = self.get_random_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    return IPInfo(
                        ip=data.get('ip', ip),
                        country=data.get('country', 'N/A'),
                        city=data.get('city', 'N/A'),
                        region=data.get('region', 'N/A'),
                        org=data.get('org', 'N/A'),
                        postal=data.get('postal', 'N/A'),
                        timezone=data.get('timezone', 'N/A'),
                        asn=data.get('org', 'N/A').split()[0] if data.get('org') else 'N/A',
                        source="ipinfo.io",
                        timestamp=datetime.now().isoformat()
                    )
                    
        except Exception as e:
            logging.error(f"IPInfo.io error: {e}")
            
        return None

    async def get_ipapi_data(self, ip: str) -> Optional[IPInfo]:
        """Get IP information from ipapi.co"""
        try:
            url = f"https://ipapi.co/{ip}/json/"
            
            # Check robots.txt
            if not await self.check_and_respect_robots(url, '*'):
                return None
                
            headers = self.get_random_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    return IPInfo(
                        ip=data.get('ip', ip),
                        country=data.get('country_name', 'N/A'),
                        city=data.get('city', 'N/A'),
                        region=data.get('region', 'N/A'),
                        org=data.get('org', 'N/A'),
                        postal=data.get('postal', 'N/A'),
                        timezone=data.get('timezone', 'N/A'),
                        asn=data.get('asn', 'N/A'),
                        source="ipapi.co",
                        timestamp=datetime.now().isoformat()
                    )
                    
        except Exception as e:
            logging.error(f"IPAPI.co error: {e}")
            
        return None

    async def check_iplogger(self, ip: str) -> Dict[str, Any]:
        """Check IP logger information"""
        try:
            # Conceptual implementation - in practice, you'd need specific APIs
            return {
                "ip": ip,
                "source": "iplogger.org",
                "info": "IP Logger detection requires specific API implementation",
                "risk_level": "Unknown",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"IP Logger check error: {e}")
            return {}

    async def check_whatismyipaddress(self, ip: str) -> Dict[str, Any]:
        """Check IP information from whatismyipaddress.com"""
        try:
            url = f"https://whatismyipaddress.com/ip/{ip}"
            
            # Check robots.txt
            if not await self.check_and_respect_robots(url, '*'):
                return {}
                
            headers = self.get_random_headers()
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Extract information from the page
                    info_sections = soup.find_all('div', class_='info')
                    ip_info = {}
                    
                    for section in info_sections:
                        text = section.get_text()
                        if 'Country' in text:
                            ip_info['country'] = text.split(':')[-1].strip()
                        elif 'State/Region' in text:
                            ip_info['region'] = text.split(':')[-1].strip()
                        elif 'City' in text:
                            ip_info['city'] = text.split(':')[-1].strip()
                        elif 'ISP' in text:
                            ip_info['isp'] = text.split(':')[-1].strip()
                    
                    return {
                        "ip": ip,
                        "source": "whatismyipaddress.com",
                        "details": ip_info,
                        "timestamp": datetime.now().isoformat()
                    }
                    
        except Exception as e:
            logging.error(f"WhatIsMyIPAddress check error: {e}")
            
        return {}

    async def search_keywords(self, keywords: List[str], num_results: int = 10) -> List[SearchResult]:
        """Search for keywords across multiple search engines"""
        all_results = []
        search_tasks = []
        
        for keyword in keywords:
            # Create tasks for each search engine - FIXED: properly reference the methods
            search_tasks.append(self.search_google(keyword, num_results))
            search_tasks.append(self.search_duckduckgo(keyword, num_results))
            search_tasks.append(self.search_bing(keyword, num_results))
            search_tasks.append(self.search_yahoo(keyword, num_results))
            search_tasks.append(self.search_brave(keyword, num_results))
        
        # Execute all search tasks concurrently
        results = await asyncio.gather(*search_tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                all_results.extend(result)
            elif isinstance(result, Exception):
                logging.error(f"Search task failed: {result}")
        
        return all_results

    async def investigate_ip(self, ip: str) -> Dict[str, Any]:
        """Investigate IP address across multiple services"""
        ip_info_tasks = [
            self.get_ipinfo_data(ip),
            self.get_ipapi_data(ip),
            self.check_iplogger(ip),
            self.check_whatismyipaddress(ip)
        ]
        
        results = await asyncio.gather(*ip_info_tasks, return_exceptions=True)
        
        ip_investigation = {
            "ip": ip,
            "services_checked": [],
            "detailed_info": [],
            "summary": {},
            "investigation_date": datetime.now().isoformat()
        }
        
        for result in results:
            if isinstance(result, IPInfo):
                ip_investigation["services_checked"].append(result.source)
                ip_investigation["detailed_info"].append({
                    "source": result.source,
                    "country": result.country,
                    "city": result.city,
                    "region": result.region,
                    "organization": result.org,
                    "asn": result.asn,
                    "timezone": result.timezone,
                    "timestamp": result.timestamp
                })
            elif isinstance(result, dict) and result:
                ip_investigation["services_checked"].append(result.get("source", "Unknown"))
                ip_investigation["detailed_info"].append(result)
            elif isinstance(result, Exception):
                logging.error(f"IP investigation task failed: {result}")
        
        # Create summary
        if ip_investigation["detailed_info"]:
            summary = {}
            for info in ip_investigation["detailed_info"]:
                if isinstance(info, dict):
                    for key, value in info.items():
                        if key not in ['source', 'ip', 'timestamp'] and value != 'N/A':
                            if key not in summary:
                                summary[key] = set()
                            if value and value != 'N/A':
                                summary[key].add(str(value))
            
            ip_investigation["summary"] = {k: list(v) for k, v in summary.items()}
        
        return ip_investigation

    def save_results_json(self, results: List[SearchResult], filename: str = "search_results.json"):
        """Save search results to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump([{
                    'source': r.source,
                    'title': r.title,
                    'url': r.url,
                    'snippet': r.snippet,
                    'keywords': r.keywords,
                    'timestamp': r.timestamp
                } for r in results], f, indent=2, ensure_ascii=False)
            logging.info(f"JSON results saved to {filename}")
            print_green(f"📄 JSON report saved: {filename}")
        except Exception as e:
            logging.error(f"Error saving JSON results: {e}")
            print_red(f"❌ Error saving JSON: {e}")

    def save_results_csv(self, results: List[SearchResult], filename: str = "search_results.csv"):
        """Save search results to CSV file"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Source', 'Title', 'URL', 'Snippet', 'Keywords', 'Timestamp'])
                
                for result in results:
                    writer.writerow([
                        result.source,
                        result.title[:100] + '...' if len(result.title) > 100 else result.title,
                        result.url,
                        result.snippet[:150] + '...' if len(result.snippet) > 150 else result.snippet,
                        '|'.join(result.keywords),
                        result.timestamp
                    ])
            logging.info(f"CSV results saved to {filename}")
            print_green(f"📊 CSV report saved: {filename}")
        except Exception as e:
            logging.error(f"Error saving CSV results: {e}")
            print_red(f"❌ Error saving CSV: {e}")

    def save_results_txt(self, results: List[SearchResult], filename: str = "search_results.txt"):
        """Save search results to TXT file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("SEARCH RESULTS REPORT\n")
                f.write("=" * 60 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Results: {len(results)}\n")
                f.write(f"Search Keywords: {', '.join(set(k for r in results for k in r.keywords))}\n\n")
                
                # Group by source
                sources = {}
                for result in results:
                    if result.source not in sources:
                        sources[result.source] = []
                    sources[result.source].append(result)
                
                for source, source_results in sources.items():
                    f.write(f"\n{source.upper()} RESULTS ({len(source_results)} found)\n")
                    f.write("-" * 40 + "\n")
                    
                    for i, result in enumerate(source_results, 1):
                        f.write(f"\nResult #{i}:\n")
                        f.write(f"Title: {result.title}\n")
                        f.write(f"URL: {result.url}\n")
                        f.write(f"Snippet: {result.snippet}\n")
                        f.write(f"Keywords: {', '.join(result.keywords)}\n")
                        f.write(f"Timestamp: {result.timestamp}\n")
                        f.write("-" * 30 + "\n")
                    
            logging.info(f"TXT results saved to {filename}")
            print_green(f"📝 TXT report saved: {filename}")
        except Exception as e:
            logging.error(f"Error saving TXT results: {e}")
            print_red(f"❌ Error saving TXT: {e}")

    def save_ip_report_json(self, ip_report: Dict[str, Any], filename: str = "ip_report.json"):
        """Save IP investigation report to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(ip_report, f, indent=2, ensure_ascii=False)
            logging.info(f"JSON IP report saved to {filename}")
            print_green(f"📄 JSON IP report saved: {filename}")
        except Exception as e:
            logging.error(f"Error saving JSON IP report: {e}")
            print_red(f"❌ Error saving JSON IP report: {e}")

    def save_ip_report_csv(self, ip_report: Dict[str, Any], filename: str = "ip_report.csv"):
        """Save IP investigation report to CSV file"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address', 'Service', 'Country', 'City', 'Region', 'Organization', 'ASN', 'Timezone', 'Timestamp'])
                
                for info in ip_report.get('detailed_info', []):
                    if isinstance(info, dict):
                        writer.writerow([
                            ip_report['ip'],
                            info.get('source', 'N/A'),
                            info.get('country', 'N/A'),
                            info.get('city', 'N/A'),
                            info.get('region', 'N/A'),
                            info.get('organization', 'N/A'),
                            info.get('asn', 'N/A'),
                            info.get('timezone', 'N/A'),
                            info.get('timestamp', 'N/A')
                        ])
            logging.info(f"CSV IP report saved to {filename}")
            print_green(f"📊 CSV IP report saved: {filename}")
        except Exception as e:
            logging.error(f"Error saving CSV IP report: {e}")
            print_red(f"❌ Error saving CSV IP report: {e}")

    def save_ip_report_txt(self, ip_report: Dict[str, Any], filename: str = "ip_report.txt"):
        """Save IP investigation report to TXT file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("IP INVESTIGATION REPORT\n")
                f.write("=" * 60 + "\n")
                f.write(f"IP Address: {ip_report['ip']}\n")
                f.write(f"Investigation Date: {ip_report.get('investigation_date', 'N/A')}\n")
                f.write(f"Services Checked: {', '.join(ip_report.get('services_checked', []))}\n\n")
                
                f.write("DETAILED INFORMATION:\n")
                f.write("-" * 40 + "\n")
                for info in ip_report.get('detailed_info', []):
                    if isinstance(info, dict):
                        f.write(f"\nService: {info.get('source', 'Unknown')}\n")
                        for key, value in info.items():
                            if key not in ['source', 'ip'] and value and value != 'N/A':
                                f.write(f"  {key.replace('_', ' ').title()}: {value}\n")
                
                if ip_report.get('summary'):
                    f.write("\nSUMMARY:\n")
                    f.write("-" * 40 + "\n")
                    for key, value in ip_report['summary'].items():
                        if value:
                            f.write(f"{key.replace('_', ' ').title()}: {', '.join(value)}\n")
                    
            logging.info(f"TXT IP report saved to {filename}")
            print_green(f"📝 TXT IP report saved: {filename}")
        except Exception as e:
            logging.error(f"Error saving TXT IP report: {e}")
            print_red(f"❌ Error saving TXT IP report: {e}")

    def save_all_formats(self, results: List[SearchResult], ip_report: Dict[str, Any], output_prefix: str):
        """Save results in all formats (JSON, CSV, TXT)"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if results:
            base_name = f"{output_prefix}_search_{timestamp}" if output_prefix else f"search_results_{timestamp}"
            self.save_results_json(results, f"{base_name}.json")
            self.save_results_csv(results, f"{base_name}.csv")
            self.save_results_txt(results, f"{base_name}.txt")
            
        if ip_report:
            base_name = f"{output_prefix}_ip_report_{timestamp}" if output_prefix else f"ip_report_{timestamp}"
            self.save_ip_report_json(ip_report, f"{base_name}.json")
            self.save_ip_report_csv(ip_report, f"{base_name}.csv")
            self.save_ip_report_txt(ip_report, f"{base_name}.txt")

async def main():
    # Print the banner first
    print_banner()
    
    parser = argparse.ArgumentParser(
        description=f'{Colors.GREEN}Advanced Web Scraping Bot - Multi-Search Engine & IP Intelligence Tool{Colors.END}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Colors.GREEN}{Colors.BOLD}🚀 USAGE EXAMPLES:{Colors.END}

{Colors.GREEN}  # Search for keywords{Colors.END}
  {Colors.BLUE}python3 scraper_bot.py --keywords "cybersecurity" "data breach" --results 20{Colors.END}

{Colors.GREEN}  # Investigate IP address{Colors.END}
  {Colors.BLUE}python3 scraper_bot.py --ip "8.8.8.8"{Colors.END}

{Colors.GREEN}  # Combined search{Colors.END}
  {Colors.BLUE}python3 scraper_bot.py --keywords "malware" --ip "192.168.1.1" --output my_report{Colors.END}

{Colors.GREEN}  # Using short options{Colors.END}
  {Colors.BLUE}python3 scraper_bot.py -k "password" "security" -r 15 -o security_report{Colors.END}

{Colors.GREEN}  # Format options{Colors.END}
  {Colors.BLUE}python3 scraper_bot.py --keywords "test" --format csv{Colors.END}
  {Colors.BLUE}python3 scraper_bot.py --ip "8.8.8.8" --format all{Colors.END}
  {Colors.BLUE}python3 scraper_bot.py -k "security" -f txt{Colors.END}

{Colors.GREEN}  # Help command{Colors.END}
  {Colors.BLUE}python3 scraper_bot.py --help{Colors.END}

{Colors.YELLOW}📋 Note: Be respectful to servers and comply with robots.txt and terms of service.{Colors.END}
        '''
    )
    
    parser.add_argument('--keywords', '-k', nargs='+', help='Keywords to search for')
    parser.add_argument('--ip', help='IP address to investigate')
    parser.add_argument('--results', '-r', type=int, default=10, help='Number of results per search (default: 10)')
    parser.add_argument('--output', '-o', help='Output filename prefix')
    parser.add_argument('--format', '-f', choices=['json', 'csv', 'txt', 'all'], default='all', 
                       help='Output format (default: all)')
    
    args = parser.parse_args()
    
    if not args.keywords and not args.ip:
        print_red("❌ Error: Please provide either keywords or an IP address to investigate.")
        print()
        parser.print_help()
        return
    
    async with AdvancedScrapingBot() as bot:
        search_results = []
        ip_report = {}
        
        if args.keywords:
            print_green(f"🔍 Searching for keywords: {', '.join(args.keywords)}")
            print_blue(f"📊 Target results per search: {args.results}")
            print_yellow("⏳ Please wait while we gather results from multiple search engines...")
            print_yellow("🤖 Checking robots.txt and respecting crawl delays...")
            
            search_results = await bot.search_keywords(args.keywords, args.results)
            
            print_green(f"\n✅ SEARCH COMPLETED")
            print_blue(f"📈 Total results found: {len(search_results)}")
            
            # Group results by source
            sources = {}
            for result in search_results:
                if result.source not in sources:
                    sources[result.source] = 0
                sources[result.source] += 1
            
            print_yellow(f"🔧 Sources: {', '.join([f'{k}({v})' for k, v in sources.items()])}")
            
            if search_results:
                print_green(f"\n📋 TOP 10 RESULTS:")
                print("=" * 80)
                for i, result in enumerate(search_results[:10], 1):
                    print_blue(f"\n#{i} | Source: {result.source}")
                    print(f"Title: {result.title}")
                    print(f"URL: {result.url}")
                    print(f"Snippet: {result.snippet[:150]}...")
                    print("-" * 80)
            else:
                print_red("❌ No results found. This could be due to:")
                print_red("   - Network connectivity issues")
                print_red("   - Robots.txt restrictions")
                print_red("   - Search engine blocking requests")
                print_red("   - Changes in website structure")
        
        if args.ip:
            if bot.is_ip_address(args.ip):
                print_green(f"\n🌐 Investigating IP address: {args.ip}")
                print_yellow("⏳ Gathering information from multiple IP lookup services...")
                print_yellow("🤖 Checking robots.txt and respecting crawl delays...")
                
                ip_report = await bot.investigate_ip(args.ip)
                
                print_green(f"\n✅ IP INVESTIGATION COMPLETED")
                print_blue(f"📍 IP: {ip_report['ip']}")
                print_yellow(f"🔧 Services checked: {', '.join(ip_report['services_checked'])}")
                
                if ip_report['detailed_info']:
                    print_green(f"\n📊 DETAILED INFORMATION:")
                    print("=" * 80)
                    for info in ip_report['detailed_info']:
                        if isinstance(info, dict):
                            print_blue(f"\n📡 Source: {info.get('source', 'Unknown')}")
                            for key, value in info.items():
                                if key not in ['source', 'ip', 'details', 'timestamp'] and value and value != 'N/A':
                                    print(f"  • {key.replace('_', ' ').title()}: {value}")
                            if 'details' in info and info['details']:
                                print(f"  • Additional Details:")
                                for detail_key, detail_value in info['details'].items():
                                    if detail_value:
                                        print(f"    - {detail_key}: {detail_value}")
                            print("-" * 80)
                    
                    if ip_report['summary']:
                        print_green(f"\n📈 SUMMARY:")
                        for key, value in ip_report['summary'].items():
                            if value:
                                print(f"  • {key.replace('_', ' ').title()}: {', '.join(value)}")
                else:
                    print_red("❌ No IP information retrieved. This could be due to:")
                    print_red("   - Network connectivity issues")
                    print_red("   - API rate limiting")
                    print_red("   - Invalid IP address")
            else:
                print_red(f"❌ Error: {args.ip} is not a valid IP address")
        
        # Save results in specified formats
        if search_results or ip_report:
            print_green(f"\n💾 SAVING REPORTS...")
            
            if args.format == 'all' or args.output:
                bot.save_all_formats(search_results, ip_report, args.output or "")
                print_green("✅ Reports saved in JSON, CSV, and TXT formats")
            else:
                if search_results:
                    base_name = f"{args.output}_search" if args.output else "search_results"
                    if args.format == 'json':
                        bot.save_results_json(search_results, f"{base_name}.json")
                    elif args.format == 'csv':
                        bot.save_results_csv(search_results, f"{base_name}.csv")
                    elif args.format == 'txt':
                        bot.save_results_txt(search_results, f"{base_name}.txt")
                
                if ip_report:
                    base_name = f"{args.output}_ip_report" if args.output else "ip_report"
                    if args.format == 'json':
                        bot.save_ip_report_json(ip_report, f"{base_name}.json")
                    elif args.format == 'csv':
                        bot.save_ip_report_csv(ip_report, f"{base_name}.csv")
                    elif args.format == 'txt':
                        bot.save_ip_report_txt(ip_report, f"{base_name}.txt")
                
                print_green(f"✅ Reports saved in {args.format.upper()} format")

if __name__ == "__main__":
    asyncio.run(main())