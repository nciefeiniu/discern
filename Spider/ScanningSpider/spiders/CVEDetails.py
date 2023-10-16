import json
import re
import scrapy
import util

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ScanningSpider.items import CVEItem
from ScanningSpider.items import CVEDetailItem


class CVEDetails(scrapy.Spider):
    name = "cve_detail"
    allowed_domains = ['cvedetails.com', 'cveapi.com']
    base_url = 'https://www.cvedetails.com/vulnerability-list/year-'
    baer_detail_url = "https://www.cvedetails.com/"

    # start_urls = ['https://www.cvedetails.com/vulnerability-list/year-2019/vulnerabilities.html']

    # 初始页面入口：
    def start_requests(self):
        for year in range(2019, 1998, -1):
            url = self.base_url + str(year) + '/vulnerabilities.html'
            yield scrapy.Request(url, self.parseList)

    # 分页入口：
    def parseList(self, response):
        soup = BeautifulSoup(response.text, 'lxml')

        for page in soup.find('div', {'id': 'pagingb'}).find_all('a', href=True):
            _url = urljoin(response.url, page['href'])
            yield scrapy.Request(_url, self.parseInfo)

    def parse_cve_json(self, response):
        _data = json.loads(response.text)
        cve = CVEItem()
        cve['description'] = _data['cve'].get("description", {}).get('description_data')[0]['value']
        cve['cve_id'] = _data['cve']['CVE_data_meta']['ID']
        cve['cve_url'] = f'/cve/{cve["cve_id"]}/'
        cve['cwe_id'] = ''

        cve['exp'] = ''
        cve['vulnerability_type'] = ''
        cve['score'] = _data['impact']['baseMetricV2']['cvssV2']['baseScore']
        cve['gainedaccess_level'] = ''
        cve['access'] = _data['impact']['baseMetricV2']['cvssV2']['accessVector']
        cve['complexity'] = _data['impact']['baseMetricV2']['cvssV2']['accessComplexity']
        cve['authentication'] = _data['impact']['baseMetricV2']['cvssV2']['authentication']
        cve['confidentiality'] = _data['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
        cve['integrity'] = _data['impact']['baseMetricV2']['cvssV2']['integrityImpact']
        cve['availability'] = _data['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
        yield cve
        detail = CVEDetailItem()
        detail['cve_id'] = _data['cve']['CVE_data_meta']['ID']
        detail['product_type'] = ''
        detail['vendor'] = ''
        detail['product'] = ''
        detail['version'] = ''
        vendor_data = _data['cve'].get('affects', {}).get('vendor', {}).get('vendor_data', [])
        if vendor_data:
            detail['vendor'] = vendor_data[0]['vendor_name']
            product_data = vendor_data[0]['product']['product_data']
            if product_data:
                detail['product'] = product_data[0]['product_name']
                version_data = product_data[0]['version']['version_data']
                if version_data:
                    detail['version'] = ','.join([f'{_["version_affected"]}{_["version_value"]}' for _ in version_data])
        detail['update'] = ""
        detail['edition'] = ""
        detail['language'] = ""
        yield detail

    # 分页处理：
    def parseInfo(self, response):
        soup = BeautifulSoup(response.text, 'lxml')
        page_result = soup.find('div', {'id': 'searchresults'})
        for item in page_result.find_all('div'):
            _id = item.find('h3', {'data-tsvfield': 'cveId'})
            if _id:
                cve_id = _id.get_text(strip=True)
                yield scrapy.Request(f'https://v1.cveapi.com/{cve_id}.json', self.parse_cve_json)
