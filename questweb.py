#!/usr/bin/env python

#
# InfoWeb . Version 3.0
# InfoWeb - Information Gathering Tool
############################################
# Coder   : Bozkurt 
############################################

from urllib import *
from platform import system
import sys
import time
import os
from urllib.request import urlopen
import requests
import geoip2.database
import ipaddress
import nmap 
from prettytable import PrettyTable
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys
import socket
import struct
import io
import re
import json
import subprocess
import whois
from dns.resolver import query, NoAnswer
from tldextract import extract
from urllib.parse import urlparse
from ipwhois import IPWhois
from ipaddress import IPv4Address,IPv4Network
from operator import itemgetter
import dns.resolver




#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk reverse ip

def reverse_ip_lookup_apisiz(domain):
        # Sonuçları tablo şeklinde görüntülemek için PrettyTable nesnesi oluştur
    result_table = PrettyTable()
    result_table.field_names = ["DOMAIN", "RESOLVED DATE"]

    

    # Selenium ile domaini siteye yaz.
    # Chrome tarayıcısını başsız modda başlat
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--headless")
    driver = webdriver.Chrome(options=chrome_options)

    # Hedef web sitesini ziyaret etme
    url = f"https://viewdns.info/reverseip/?host={domain}&t=1"
    driver.get(url)
    time.sleep(2)

    try:
        # Sayfa açıldıktan sonra bekleme
        time.sleep(3)

        # Sayfanın tam HTML içeriğini al
        html_content = driver.page_source

    except Exception as e:
        print(f'Hata: {e}')

    # HTML içeriğini Beautiful Soup ile parse et
    soup = BeautifulSoup(html_content, 'html.parser')

    # Tüm işime yarayacak nesneleri al
    objects = soup.find('table', border='1')

    # Tablonun içindeki hücreleri bul
    cells = objects.find_all('td')

    # Hücre verilerini düzenli bir şekilde al
    domain_data = []
    current_domain = ""
    for cell in cells:
        cell_text = cell.text.strip()
        if cell_text.endswith((".com", ".ir",".tk",".net", ".tr", ".online", ".xyz", ".org", ".site",".biz",".edu",".gov",".mil",".co",".io",".info",".biz")):
            current_domain = cell_text
        elif current_domain and cell_text:
            result_table.add_row([current_domain, cell_text])
            domain_data.append([current_domain, cell_text])
            
    # Hücre verilerini ekrana yazdır
    # Satır sayısını ekrana yazdır
    num_rows = len(result_table.get_string().split('\n')) - 4
    print(f"\033[92mBu sunucuda {num_rows} adet domain barındırılmaktadır.\n")
    print(f"\033[91m{result_table}")
    print("\n")



#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk whois lookup


def whois_lookup(domain_name):
    domain = whois.whois(domain_name)
    #print(domain)



    for i in domain:
        #print(i)

        print(f"\033[91m{i}".ljust(20),":"f"\033[92m{domain[i]}")



#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk dns lookup






#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk get location

def get_location(ip_address):
    # IP adresinin coğrafi konumunu belirlemek için bir servisten veri al
    response = requests.get(f'https://freegeoip.app/json/{ip_address}')
    data = response.json()

    # Coğrafi konumu ayrıntıları ekrana yazdır
    print("\033[1;93m\nIP Adresi" .ljust(20)+      "\t= "     f"{ip_address}")
    print("Ülke"                .ljust(20)+      "= "     f"{data['country_name']}")
    print("Ülke Kodu"           .ljust(20)+      "= "     f"{data['country_code']}")
    print("Bölge"               .ljust(20)+      "= "     f"{data['region_name']}")
    print("Şehir"               .ljust(20)+      "= "     f"{data['city']}")
    print("Posta Kodu "         .ljust(20)+      "= "     f"{data['zip_code']}")
    print("Enlem"               .ljust(20)+      "= "     f"{data['latitude']}")
    print("Boylam"              .ljust(20)+      "= "     f"{data['longitude']}")
    print("Zaman Dilimi"        .ljust(20)+      "= "     f"{data['time_zone']}")


#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk subnet lookup


def subnet_lookup(ip_address):
    IP_Addr = ipaddress.ip_interface(ip_address)  


    Address = IP_Addr
    Net_Addr = IP_Addr.network
    pref_len = IP_Addr.with_prefixlen
    Mask = IP_Addr.netmask
    wildcard = IP_Addr.hostmask
    broadcast_address = Net_Addr.broadcast_address


    print('\033[1;92m\nAddress '.ljust(20),'\t\t= ', str(Net_Addr).split('/')[0])
    print('Network Address '.ljust(20),'= ' ,str(Net_Addr))
    print('CIDR Notation '.ljust(20),'= ', pref_len.split('/')[1])
    print('Broadcast Address '.ljust(20),'= ', broadcast_address)
    print('Subnet Mask '.ljust(20),'= ', Mask)
    print('Wildcard Mask '.ljust(20),'= ', wildcard)
    print('First IP '.ljust(20),'= ', list(Net_Addr.hosts())[0])
    print('Last IP '.ljust(20),'= ' , list(Net_Addr.hosts())[-1])
    print('Host Range '.ljust(20),'= ',list(Net_Addr.hosts())[0],'-',list(Net_Addr.hosts())[-1]  )
    print('Ip Version '.ljust(20),'= ',IP_Addr.version )



#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk port scan


def port_scan(ip_address):

    # nmap tarama nesnesini oluştur
    nm = nmap.PortScanner()

    # Belirtilen portları tarayarak hedef IP adresini kontrol et
    nm.scan(ip_address, arguments='-p 21,22,23,25,53,80,110,111,143,443,445,465,993,3306,3389')  # FTP ve SSH portlarını tarıyoruz


    # Sonuçları tablo şeklinde görüntülemek için PrettyTable nesnesi oluştur
    result_table = PrettyTable()
    result_table.field_names = ["PORT", "STATE", "SERVICE"]


    # Tarama sonuçlarını işle
    for host in nm.all_hosts():
        for protocol in ['tcp', 'udp']:
            if protocol in nm[host]:
                for port, port_info in nm[host][protocol].items():
                    if port in [21,22,23,25,53,80,110,111,143,443,445,465,993,3306,3389]:
                        state = port_info['state']
                        service = port_info['name']
                        result_table.add_row([f"{port}/{protocol}", state, service])


    print(f"\033[1;95m{result_table}\033[0m")




#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk extract external  links

def is_external(link, base_url):
    # Verilen bağlantının harici olup olmadığını kontrol et
    absolute_link = urljoin(base_url, link)
    return not absolute_link.startswith(base_url)

def extract_external_links(url):
    try:
        # URL'den sayfa içeriğini al
        response = requests.get(url)
        response.raise_for_status()

        # BeautifulSoup kullanarak HTML içeriğini analiz et
        soup = BeautifulSoup(response.text, 'html.parser')

        # Tüm bağlantıları al
        links = soup.find_all('a', href=True)

        # Harici bağlantıları filtrele
        external_links = [link['href'] for link in links if is_external(link['href'], url)]

        

        print(f"\033[1;92mHarici Bağlantılar \t ({url}) \n \033[0m")
        for link in external_links:
            print(f"\033[1;91m{link}")


    except requests.exceptions.RequestException as e:
        print(f"Hata: {e}")
        return []



#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk http header


def http_header(domain):
    url = f'https://www.{domain}'
    response = requests.get(url)

    # Yanıt başlıklarını okuma
    headers = response.headers

    # En uzun key değerini bul
    max_key_length = max(len(key) for key in headers)


    # Tüm başlıkları yazdırma
    print("HTTP Headers:")
    for key, value in headers.items():

        print(f"\033[1;91m{key}".ljust(max_key_length+5),  "=" , f"\033[1;92m{value}\n")


#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk host finder


def Host_finder(url_input):
    try:
        #chrome_options = Options()
        #chrome_options.add_argument("--headless")
        #chrome_options.add_argument("--enable-javascript")  # JavaScript'i etkinleştir


        #driver = webdriver.Chrome(options=chrome_options)
        # Tarayıcı başlatma
        driver = webdriver.Chrome() #sekenium ile sitenin açılmasının kodunu yukarıda arka planda çalıştırmaya çalıştım ancak çözmediğim bir problem çıktı bunu daha düzeltirim.
        # Hedef web sitesini ziyaret etme
        url = "https://hostingchecker.com/" 
        driver.get(url)
        time.sleep(3)

        # Arama kutusunu bulma
        search_box = driver.find_element(By.CSS_SELECTOR, '[id="url"]')

        # Arama kutusuna metin gönderme
        search_box.send_keys(url_input)

        # Enter tuşuna basma
        search_box.send_keys(Keys.ENTER)

        # Sayfa açıldıktan sonra bekleme
        time.sleep(3)

        # Sayfanın tam HTML içeriğini al
        html_content = driver.page_source

        # HTML içeriğini Beautiful Soup ile parse et
        soup = BeautifulSoup(html_content, 'html.parser')

        # Tüm işime yarayacak nesneleri al
        objects = soup.find('div', class_='hcresults')
        name = soup.find_all('p')

        for index, paragraph in enumerate(name, start=1):
            if index >= 10:
                break  # döngüyü sonlandır
            if index == 2:
                continue
            print(f"\033[1;92m {paragraph.text}")
            print("\n")
            index += 10

    except Exception as e:
        print(f'Hata: {e}')

    finally:
        # Tarayıcıyı kapat
        driver.quit()

#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk trace route

class flushfile(io.IOBase):
    def __init__(self, f):
        self.f = f
    def write(self, x):
        self.f.write(x)
        self.f.flush()

sys.stdout = flushfile(sys.stdout)

def main(dest_name):
    dest_addr = socket.gethostbyname(dest_name)
    port = 33434
    max_hops = 30
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1
    while True:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        
        timeout = struct.pack("ll", 5, 0)
        recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
        
        recv_socket.bind(("", port))
        sys.stdout.write(" \033[1;92m%d  " % ttl)
        send_socket.sendto(b"", (dest_name, port))
        curr_addr = None
        curr_name = None
        finished = False
        tries = 3
        while not finished and tries > 0:
            try:
                _, curr_addr = recv_socket.recvfrom(512)
                finished = True
                curr_addr = curr_addr[0]
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            except socket.error as e:
                tries = tries - 1
                sys.stdout.write("* ")
        
        send_socket.close()
        recv_socket.close()
        
        if not finished:
            pass
        
        if curr_addr is not None:
            curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
            curr_host = ""
        sys.stdout.write("%s\n" % (curr_host))

        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break




#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk  extract_links_dynamic


def extract_links_dynamic(url):
    # URL'yi belirleyin

    #driver = webdriver.Chrome()

    # Chrome tarayıcısını başsız modda başlat
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    driver = webdriver.Chrome(options=chrome_options)

    
    driver.get(url)

    # URL'den sayfa içeriğini al
    #response = requests.get(url)
    #response.raise_for_status()


    # Sayfanın tam HTML içeriğini al
    html_content = driver.page_source


    # BeautifulSoup kullanarak HTML içeriğini parse et
    soup = BeautifulSoup(html_content, 'html.parser')

    # Tüm bağlantıları al
    links = soup.find_all('a', href=True)

    # Bağlantıları ekrana yazdır
    for link in links:
        print(link['href'])


#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk  collection email 


def collection_emails(url):
# Web sitesinin URL'sini belirleyin
    
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    driver = webdriver.Chrome(options=chrome_options)
    driver.get(url)

    # Sayfanın tam HTML içeriğini al
    html_content = driver.page_source

    # HTML içeriğini parse et
    #soup = BeautifulSoup(response.text, 'html.parser')





    # E-posta adresi için regex deseni
    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}"

    emails = re.findall(email_pattern, html_content)

    time.sleep(5)

    for i in emails:
        print(f"\033[1;95m{i}\033[0m")





  #kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk  testping



def test_ping(target_ip, source_ip="172.17.0.2", count=4):
    command = [
        'nping',
        '-c', str(count),
        '--icmp-type', '8',
        '--dest-ip', target_ip,
        '--source-ip', source_ip,
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)

        # Çıktıyı ekrana yazdırma
        print(f"\033[96m{result.stdout}")

        # Hata durumu kontrolü
        if result.returncode != 0:
            print(f"\033[38;5;21mNping hatası: {result.stderr}")

    except subprocess.TimeoutExpired:
        print("Nping işlemi zaman aşımına uğradı.")









#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk  abuse email 



def _get_abuse_emails(raw_whois):
    score = 0
    email_candidates = set()

    for line in raw_whois.splitlines():
        email_addresses = re.findall(r'[\w\.+-]+@[\w\.-]+', line)
        if email_addresses:
            abuse_references = line.count('abuse')

            if abuse_references == score:
                email_candidates = set(list(email_candidates) + email_addresses)
            elif abuse_references > score:
                email_candidates = set(email_addresses)
                score = abuse_references

    return list(email_candidates)


def _get_names(ip_address, parsed_whois):
    ip_address = IPv4Address(str(ip_address))
    names = []

    for network in parsed_whois['nets']:
        for cidr in network['cidr'].split(','):
            cidr = IPv4Network(cidr.strip())
            if ip_address in cidr and network['description']:
                names.append([cidr.prefixlen, network['description'].splitlines()[0]])
                break

    return [n[1] for n in sorted(names, key=itemgetter(0), reverse=True)]


def ip_abuse(ip_address):
    obj = IPWhois(ip_address)
    results = obj.lookup_whois(inc_raw=True)

    return {
        "value": ip_address,
        "names": _get_names(ip_address, results),
        "abuse": _get_abuse_emails(results['raw']),
        "raw": results['raw']}

def url_abuse(url):
    url = url if '://' in url else "http://" + url
    url = urlparse(url)

    parts = extract(url.netloc.split(':')[0])
    ip_addresses = set()

    if parts.registered_domain:
        answers = query(parts.registered_domain, 'A')
        for rdata in answers:
            ip_addresses.add(rdata.address)
    else:
        ip_addresses.add(parts.domain)

    results = {'value': [], 'names': [], 'abuse': [], 'raw': ""}
    for ip in ip_addresses:
        results['value'].append(ip)
        ip_results = ip_abuse(ip)
        results['raw'] += "IP: {}\n\n{}\n\n".format(ip, ip_results['raw'])
        for key in ['names', 'abuse']:
            for value in ip_results[key]:
                if value not in results[key]:
                    results[key].append(value)

    return results


#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk dnslookup

def dns_lookup(domain):

    # Sonuçları tablo şeklinde görüntülemek için PrettyTable nesnesi oluştur
    result_table = PrettyTable()
    result_table.field_names = ["\033[38;5;39mTYPE\033[0m", "\033[38;5;39mDATA\033[0m"]

    try:
        # İstenen DNS kayıtlarını tanımla
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS','PTR','SOA','TXT','SRV','CAA','HINFO']

        # Her bir kayıt türü için sorguları gerçekleştir
        for record_type in record_types:
            try:
                # Kayıt türüne göre sorgu yap
                result = dns.resolver.resolve(domain, record_type)
                
                for un in result:
                    #print(f"\033[92m{record_type} Record: {un}\033[0m")
                    un = f"\033[38;5;47m{un}\033[0m"
                    record_type =f"\033[92m{record_type}\033[0m"
                    result_table.add_row([record_type,un])


            except dns.resolver.NoAnswer:
                #print(f"\033[91m{domain} için {record_type} kaydı bulunamadı.\033[0m\n")
                record_type =f"\033[92m{record_type}\033[0m"
                result_table.add_row([record_type,"\033[91mkaydı bulunamadı\033[0m"])
        print(result_table)
    except dns.resolver.NXDOMAIN:
        print(f"{domain} için DNS kaydı bulunamadı.")
    except dns.resolver.NoAnswer:
        print(f"{domain} için DNS kaydı bulunamadı.")
    except dns.exception.DNSException as e:
        print(f"DNS sorgusu sırasında bir hata oluştu: {e}")




#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk sitemap
def crawl_site(url, depth=3):
    visited = set()

    def crawl(url, current_depth):
        if current_depth > depth or url in visited:
            return
        visited.add(url)

        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Sayfa içeriğini analiz etmek için gerekli işlemler burada yapılabilir.
            # Ancak, size sadece URL'yi yazdırmak istediğiniz belirtildiğinden, içerik analizi yapılmamıştır.

            print(f"\033[38;5;47mVisited: \033[92m{url}\033[0m")

            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                crawl(next_url, current_depth + 1)

        except Exception as e:
            print(f"Error while crawling {url}: {e}")


    crawl(url, 0)


# Örnek kullanım
#crawl_site('https://www.hdfilmcehennemi.de/ ', depth=2)






#----------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------
#--------------------------------------------------------------
#--------------------------------------------------------------
def clear():
    if system() == 'Linux':
        os.system("clear")
    if system() == 'Windows':
        os.system('cls')
        os.system('color a')
    else:
        pass

def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(2. / 100)

def slowprint2(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(0.20 / 100)

def slowprint3(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(0.04 / 100)

clear()

bannner = slowprint2("""
\033[38;5;196m 
                                ,ood8888booo,
                              ,od8           8bo,
                           ,od                   bo,
                         ,d8                       8b,
                        ,o                           o,    ,a8b
                       ,8                             8,,od8  8    
                       8'                             d8'    8b
                       8                           d8'ba    aP'
                       Y,                       o8'         aP'
                        Y8,                      YaaaP'    ba
                         Y8o                   Y8'         88
                          `Y8               ,8"           `P
                            Y8o        ,d8P'              ba
                       ooood8888888P'                  P'
                    ,od                                  8
                 ,dP     o88o                           o
                ,dP          8               bozkurt    8
               ,d'   oo       8                       ,8'
               $    d$"8      8           Y    Y  o   8"
              d    d  d8    od  ""boooooooob   d"" 8   8
              $    '8  d   ood ,   8        b  8   8  b'
              $   $ ' 8  8     d  d8        `b  d    8  b'
               $  $ '8   b    Y  d8          8 ,P     8  b'
               `$$  'Yb  b     8b 8b         8 8,      8  o,'
                    'Y  b      8o  $$o      d  b        b   $o'  

           



""")

banner = slowprint3('''\033[1;92m
     /  /\       /  /\       /  /\       /  /\    ___                  /  /\       /  /\       /  /\    
    /  /::\     /  /:/      /  /::\     /  /::\  /__/\                /  /:/_     /  /::\     /  /::\   
   /__/:/\:\   /  /:/      /  /:/\:\   /__/:/\:\ \  \:\              /  /:/ /\   /  /:/\:\   /  /:/\:\  
   \  \:\ \:\ /  /:/      /  /::\ \:\ _\_ \:\ \:\ \__\:\            /  /:/ /:/_ /  /::\ \:\ /  /::\ \:\ 
    \  \:\ \:/__/:/     //__/:/\:\ \:/__/\ \:\ \:\/  /::\          /__/:/ /:/ //__/:/\:\ \:/__/:/\:\_\:|
     \  \:\/:\  \:\    /:\  \:\ \:\_\\  \:\ \:\_\/  /:/\:\         \  \:\/:/ /:\  \:\ \:\_\\  \:\ \:\/:/
      \__\::/ \  \:\  /:/ \  \:\ \:\  \  \:\_\:\/  /:/__\/          \  \::/ /:/ \  \:\ \:\  \  \:\_\::/ 
      /  /:/   \  \:\/:/   \  \:\_\/   \  \:\/:/__/:/                \  \:\/:/   \  \:\_\/   \  \:\/:/  
     /__/:/     \  \::/     \  \:\      \  \::/\__\/                  \  \::/     \  \:\      \__\::/   
     \__\/       \__\/       \__\/       \__\/                         \__\/       \__\/          ~~    

\033[92m
\033[1;95m[\033[1;97m#@#@#@#@#\033[1;95m]\033[38;5;197mInfoWeb: Information Gathering Tool\033[1;95m[\033[1;97m#@#@#@#@\033[1;95m]

\033[1;97m==[[ \033[1;90m->>\033[1;92m Name     :\033[1;91m          InfoWeb                 \033[1;90m<<- \033[1;97m]]==
\033[1;97m==[[ \033[1;90m->>\033[1;92m Github   :\033[1;97m    https://github.com/ozan-B     \033[1;90m<<- \033[1;97m]]==
\033[1;97m==[[ \033[1;90m->>\033[1;92m Author   :\033[1;91m           Bozkurt                \033[1;90m<<- \033[1;97m]]==
\033[1;97m==[[ \033[1;90m->>\033[1;92m Version  :\033[1;95m             3.0                  \033[1;90m<<- \033[1;97m]]==
''')
print(bannner)
time.sleep(0.8)
print(banner)
time.sleep(1.2)
def menu():
   slowprint2('''
\033[1;95m[\033[97m01\033[95m] \033[90m --\033[97m>>> \033[1;92m DNS Lookup 
\033[1;95m[\033[97m02\033[95m] \033[90m --\033[97m>>> \033[1;96m Whois Lookup
\033[1;95m[\033[97m03\033[95m] \033[90m --\033[97m>>> \033[1;92m GeoIP Lookup
\033[1;95m[\033[97m04\033[95m] \033[90m --\033[97m>>> \033[1;96m Subnet Lookup
\033[1;95m[\033[97m05\033[95m] \033[90m --\033[97m>>> \033[1;92m Port Scanner
\033[1;95m[\033[97m06\033[95m] \033[90m --\033[97m>>> \033[1;96m Extract Links 
\033[1;95m[\033[97m07\033[95m] \033[90m --\033[97m>>> \033[1;92m Test Ping
\033[1;95m[\033[97m08\033[95m] \033[90m --\033[97m>>> \033[1;96m HTTP Header
\033[1;95m[\033[97m09\033[95m] \033[90m --\033[97m>>> \033[1;92m Host Finder
\033[1;95m[\033[97m10\033[95m] \033[90m --\033[97m>>> \033[1;96m IP-Locator
\033[1;95m[\033[97m11\033[95m] \033[90m --\033[97m>>> \033[1;92m Traceroute
\033[1;95m[\033[97m12\033[95m] \033[90m --\033[97m>>> \033[1;96m Extract Links Dynamic
\033[1;95m[\033[97m13\033[95m] \033[90m --\033[97m>>> \033[1;92m Host DNS Finder
\033[1;95m[\033[97m14\033[95m] \033[90m --\033[97m>>> \033[1;96m Revrse IP Lookup
\033[1;95m[\033[97m15\033[95m] \033[90m --\033[97m>>> \033[1;92m Collection Email
\033[1;95m[\033[97m16\033[95m] \033[90m --\033[97m>>> \033[1;96m Abuse Contact Lookup 
\033[1;95m[\033[97m17\033[95m] \033[90m --\033[97m>>> \033[1;92m Site Map
\033[1;95m[\033[97m18\033[95m] \033[90m --\033[97m>>> \033[1;96m About Me 
\033[1;95m[\033[97m00\033[95m] \033[90m --\033[97m>>> \033[1;91m Exit
''')
time.sleep(0.9)
slowprint("\033[1;91mScript Developed By :\033[92m Bozkurt - For Linux's Users" + "\n\n \033[93m Let's Start \033[96m --> --> --> \033[91m ")
time.sleep(0.6)

menu()
def ext():
    ex = input ('\033[92mContinue/\033[1;91mExit \033[38;5;21m->-> ')
    if ex[0].upper() == 'E' :
        print('\033[1;92mGood-bye!!!')
        exit()
    else:
        clear()
        print(banner)
        menu()
        select()

def request_info(url):
        request = requests.get(url)
        response = request.text
        print(response)


def select():
    try:
        CybernetiX = input("\033[96mEnter \033[92m00/\033[91m18 \033[38;5;47m->> ->>  ")

        if CybernetiX == "1":#dnslookup
            dz = input("\033[96mEnter Your Domain :\t\033[96m")
            print("\n")
            dns_lookup(dz)
            print("\n")
            ext()

        elif CybernetiX == "2":#whois lookup
            dz = input('\033[91mEnter IP Address :\t \033[91m')
            print("\n")
            whois_lookup(dz)
            print("\n")
            ext()
        
        
        elif CybernetiX == "3":#geoiplookup
            dz = input('\033[91mEnter IP Address : \033[91m')
            get_location(dz)
            print("\n")
            ext()
        elif CybernetiX == "4":#subnet lookup
            dz = input('\033[92mEnter IP Address : \033[92m')
            subnet_lookup(dz)
            ext()
        elif CybernetiX == "5":#port scan
            dz = input('\033[96mEnter IP Address : \033[96m')
            port_scan(dz)
            ext()
        elif CybernetiX == "6":#extract links
            dz = input('\033[91mEnter Your Domain :\t\033[91m')
            print("\n")
            extract_external_links(dz)
            ext()
        elif CybernetiX == "7":#test-ip
            dz = input('\033[92mEnter Your IP Address :\033[92m')
            test_ping(dz)
            ext()
        elif CybernetiX == "8":#http header 
            dz = input('\033[96mEnter Your Domain :\033\t[96m')
            print("\n")
            http_header(dz)
            ext()
        elif CybernetiX == "9":#host finder
            dz = input('\033[91mEnter Your Domain :\t\033[91m')
            print("\n")
            Host_finder(dz)
            ext()
        elif CybernetiX == "10":#ip locator
            dz = input('\033[91mEnter Your IP Address :\033[91m')
            print("\n")
            get_location(dz)
            ext()
        elif CybernetiX== "11":#trace-route
            dz = input('\033[1;91mEnter Domain: \033[1;m')
            main(dz)
            ext()
        elif CybernetiX == "12":#extract linx dynamic
            dz = input('\033[91mEnter Your URL :\t\033[91m')
            print("\n")
            extract_links_dynamic(dz)
            ext()
       
        elif CybernetiX == "13":#host dns finder
            dz = input('\033[92mEnter domain name : \033[92m')
            Host_finder(dz)
            ext()
            
        elif CybernetiX == "14":#reverse ip lookup
            dz = input('\033[91mEnter Your Domain :\t\033[91m')
            print("\n")
            reverse_ip_lookup_apisiz(dz)
            print("\n")
            ext()

        elif CybernetiX == "15":#collection email
            dz = input('\033[91mEnter Your URL :\t\033[91m')
            print("\n")
            collection_emails(dz)
            ext()

        elif CybernetiX == "16":#abuse lookup
            dz = input('\033[91mEnter Your Domain :\033[91m')
            ozan=url_abuse(dz)
            print("\n")
            print("Abuse Information:")
            print(f"Abuse Email: {', '.join(ozan['abuse'])}") 
            print("\n")
            ext()
        elif CybernetiX == "17":#sitemap
            dz = input('\033[91mEnter Your url :\033[91m')
            dp = int(input('\033[91mEnter depth value :\033[91m'))
            print("\n")  
            crawl_site(dz, depth=dp)
            ext()
        elif CybernetiX == "18":#about me
            slowprint("\033[38;5;21m..................... ")
            slowprint("\033[1;97mName : InfoWeb ")
            slowprint("\033[38;5;21m......................")
            slowprint("\033[1;95mVersion : 3.0 ")
            slowprint("\033[38;5;21m......................")
            slowprint("\033[1;93mAuthor : bozkurt ")
            slowprint("\033[38;5;21m......................")
            slowprint("\033[1;92mGitHub : https://github.com/ozan-B")
            slowprint("\033[38;5;21m......................")
            ext()
        elif  CybernetiX == "00":
            print ("Good-bye!!")
    except(KeyboardInterrupt):
        print ("\nCtrl + C -> Exiting!!")


if __name__ == "__main__":
    select()
