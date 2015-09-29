import unittest
import time
import traceback
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait

class AwsUIActions(unittest.TestCase):


    def __init__(self, conf, account_name=None, user_name=None, password=None, proxy=0, proxy_ip=None, proxy_port=None):
        firefoxProfile = webdriver.FirefoxProfile()

        firefoxProfile.set_preference('browser.download.useDownloadDir', True)
        firefoxProfile.set_preference('browser.download.folderList', 2)
        firefoxProfile.set_preference('browser.download.dir', conf.web_download_dir)
        firefoxProfile.set_preference('browser.download.manager.showWhenStarting', False)
        firefoxProfile.set_preference('browser.helperApps.neverAsk.saveToDisk', "application/csv, text/csv")
        firefoxProfile.set_preference('browser.helperApps.neverAsk.openFile', "application/csv, text/csv")
        if proxy == 1:
            firefoxProfile.set_preference('network.proxy.type', proxy)
            firefoxProfile.set_preference('network.proxy.http', proxy_ip)
            firefoxProfile.set_preference('network.proxy.http_port', proxy_port)
            
        self.driver = webdriver.Firefox(firefoxProfile)
        self.account_name = account_name
        self.user_name = user_name
        self.password = password



    def loginAttempt(self, account_name=None, user_name=None, password=None):
        self.account_name = account_name if account_name != None else self.account_name
        self.user_name = user_name if user_name != None else self.user_name
        self.password = password if password != None else self.password
        driver = self.driver
        driver.get("https://" + self.account_name + ".signin.aws.amazon.com/console")
        self.assertIn("Amazon Web Services Sign-In", driver.title)
        elem = driver.find_element_by_name("username")
        elem.send_keys(self.user_name)
        elem = driver.find_element_by_name("password")
        elem.send_keys(self.password)
        elem.send_keys(Keys.RETURN)
        time.sleep(5)


    def regenerateUserKeys(self, location):
        driver = self.driver
        driver.get("https://console.aws.amazon.com/iam/home?region=" + location + "#users/" + self.user_name)
        WebDriverWait(driver, 10);
        #.until(
        #    EC.presence_of_element_located((By.CLASS_NAME, "btn btn-primary topMargin createAccessKey"))
        #)
        time.sleep(5)
        self.assertIn("IAM Management", driver.title)
        elem = driver.find_element_by_xpath("//button[@id='createAccessKey']")
        elem.send_keys(Keys.ENTER)
        time.sleep(5)
        elem = driver.find_element_by_xpath("//button[@id='downloadCredentials']")
        elem.send_keys(Keys.ENTER)
        time.sleep(10)

    def deleteUserKeys(self, location):
        driver = self.driver
        driver.get("https://console.aws.amazon.com/iam/home?region=" + location + "#users/" + self.user_name)
        WebDriverWait(driver, 10);
        #.until(
        #    EC.presence_of_element_located((By.CLASS_NAME, "btn btn-primary topMargin createAccessKey"))
        #)
        time.sleep(5)
        self.assertIn("IAM Management", driver.title)
        elem = driver.find_element_by_xpath("//a[@class='pointer deleteAccessKey']")
        elem.click()
        time.sleep(5)
        elem = driver.find_element_by_xpath("//button[@id='btn_submit']")
        elem.send_keys(Keys.ENTER)
        time.sleep(10)

    def tearDown(self):
        self.driver.close()

def attemptToGetUserCredentials(conf, account, valid_name, valid_pwd):

    aAcct = AwsUIActions(conf, account, valid_name)
    aAcct.loginAttempt(password=valid_pwd)
    try:
        aAcct.deleteUserKeys("us-west-2")
    except:
        print "Old key not wound"
    finally:
        aAcct.regenerateUserKeys("us-west-2")
        aAcct.tearDown()

def failUserLogins(conf, account, valid_name, numFailedAttempts):
    aAcct = AwsUIActions(conf, account, valid_name)
    while numFailedAttempts > 0:
        aAcct.loginAttempt(password="T")
        aAcct.tearDown()
        numFailedAttempts -= 1
    
    #same login test via Tokyo proxy
    aAcct = AwsUIActions(conf, account, valid_name, proxy=1, proxy_ip="52.68.248.134", proxy_port=8888)
    while numFailedAttempts > 0:
        aAcct.loginAttempt(password="T")
        aAcct.tearDown()
        numFailedAttempts -= 1   
    
