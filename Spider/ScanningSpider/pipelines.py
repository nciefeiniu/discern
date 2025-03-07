# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
import util.dataBaseUtil

import pymysql
from ScanningSpider import settings
from ScanningSpider import items
import util


class ScanningspiderPipeline:
    def open_spider(self, spider):
        # 打开数据库连接
        print('open db')
        self.db = pymysql.connect(host=settings.MYSQL_HOST, user=settings.MYSQL_USER, password=settings.MYSQL_PASSWORD,
                                  db=settings.MYSQL_DB_NAME)

    def process_item(self, item, spider):
        if isinstance(item, items.CVEItem):
            util.dataBaseUtil.cveItemInsert(self.db, item)
        if isinstance(item, items.CVEDetailItem):
            util.dataBaseUtil.cveProductIneset(self.db, item)
        return item

    def close_spider(self, spider):
        self.db.close()
