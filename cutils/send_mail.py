from email import utils
import smtplib
import sys, traceback
import email.utils
from email.mime.text import MIMEText
import logging

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)

class SendMail(object):
    """
    Sends emails through a sendmail server. Does TLS is necessary.
    """
    def __init__(self):
        """
        Create new RmtExec object.
        """
        self.emailList = list()
        self.debug = True

    def addEmail(self, email):
        """
        Adds email to the list to be sent emails
        :param email: email dictionary
        """
        self.emailList.append(email)

    def _connect(self, name, port=smtplib.SMTP_PORT, username=None, password=None, startTls=False):
        """
        Connects to a server
        :param name: server DNS name
        :param port: server SMTP port
        """
        logging.info("Connecting to %s:%d", name, port)
        server = smtplib.SMTP(name, port)
        try:
            server.set_debuglevel(self.debug)

            # identify ourselves, prompting server for supported features
            server.ehlo()

            # If we can encrypt this session, do it
            if server.has_extn('STARTTLS') or startTls == True:
                server.starttls()
                server.ehlo() # re-identify ourselves over TLS connection
            for i in server.esmtp_features.keys():
                logging.info("Key: " + i)
            if username is not None and "auth" in server.esmtp_features.keys():
                server.login(username, password)
        except Exception, e:
            logging.error("Exception: " + str(e))
            server.quit()
            return None
        return server


    def connectAndSend(self, name, port=smtplib.SMTP_PORT, username=None, password=None,
                       email=None, startTls=False):
        """
        Connects to a server
        :param name: server DNS name
        :param port: server SMTP port
        """
        server = None
        try:
            server = self._connect(name, port, username, password, startTls)
            if email is not None:
                msg = self._format_message(email)
                logging.info("Email from " + msg.as_string())
                server.sendmail(email["from"], email["from"], msg.as_string())
                return
            for em in self.emailList:
                msg = self._format_message(em)
                server.sendmail(email["from"], msg["To"], msg.as_string())
        finally:
            if server is not None:
                server.quit()

    def _format_message(self, mail):
        msg = MIMEText(mail["body"])
        msg.set_unixfrom('author')
        to = ""
        for rcp in mail["toList"]:
            if "" != to:
                to += ", "
            to += utils.formataddr(('Recipient', rcp))
        msg['To'] = to
        msg['From'] = utils.formataddr(('Author', mail["from"]))
        msg['Subject'] = mail['subject']
        return msg

if __name__ == "__main__":
   rc = 0
   try:
      sm = SendMail()
      email = dict()
      email["from"] = "avolkov@palerra.com"
      email["toList"] = ["avolkov@palerra.com", "avolkov@palerra.com"]
      email["body"] = "this is a test message"
      email["subject"] = "test"

      sm.connectAndSend("smtp.gmail.com", username="test", email=email, startTls=True)
   except:
      traceback.print_exc()
      rc = 1
   finally:
      sys.exit(rc)
