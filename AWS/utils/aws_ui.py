import unittest
import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait

class AwsUIActions(unittest.TestCase):


    def __init__(self, account_name=None, user_name=None, password=None):
        firefoxProfile = webdriver.FirefoxProfile()

        firefoxProfile.set_preference('browser.download.folderList', 2)
        firefoxProfile.set_preference('browser.download.dir', "/tmp/webdriver-downloads")
        firefoxProfile.set_preference('browser.helperApps.neverAsk.saveToDisk', "application/csv, text/csv")

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
        profile = driver.profile
        profile.set_preference('browser.download.dir',"/tmp/webdriver-downloads")
        profile.set_preference('browser.download.manager.showWhenStarting', "false");
        profile.set_preference('browser.download.folderList', 2)
        profile.set_preference('browser.helperApps.neverAsk.saveToDisk', "application/csv, text/csv")
        elem = driver.find_element_by_xpath("//button[@id='downloadCredentials']")
        elem.send_keys(Keys.ENTER)
        time.sleep(10)


    def tearDown(self):
        self.driver.close()

def attemptToGetUserCredentials(account, valid_name, valid_pwd):

    aAcct = AwsUIActions(account, valid_name)
    aAcct.loginAttempt(password=valid_pwd)

    aAcct.regenerateUserKeys("us-west-2")
    aAcct.tearDown()

def failUserLogins(account, valid_name, numFailedAttempts):
    while numFailedAttempts > 0:
        aAcct = AwsUIActions(account, valid_name)
        aAcct.loginAttempt(password="T")
        aAcct.tearDown()
        numFailedAttempts -= 1
