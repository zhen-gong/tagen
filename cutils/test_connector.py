import traceback


class TestBase(object):
    """
    Used to reference and find tests context.
    """
    dep_base = None
    # Test sequencing.
    test_list = None

    def __init__(self):
        self.dep_base = dict()
        self.test_list = list()

    def add_test(self, test_name, test_context):
        self.dep_base[test_name] = test_context
        self.test_list.append(test_context)

    def delete_test(self, test_name):
        test_cont = self.dep_base[test_name]
        if test_cont is None:
            return
        test_cont.shutdown()
        self.dep_base[test_name] = None

    def get_test_context(self, test_name):
        for t in self.dep_base.keys():
            print str(t) + ": " + str(self.dep_base[t])
        t = self.dep_base[test_name]
        if test_name not in self.dep_base.keys():
            return None
        return self.dep_base[test_name]

    def exec_tests(self, conf):
        for t in self.test_list:
            try:
                t.run(conf)
            except:
                traceback.print_exc()

    def done(self):
        for tc in self.test_list:
            try:
                self.delete_test(tc.name)
            except:
                traceback.print_exc()

class ATest(object):
    """
    Collection of test objects.
    Also reference to a shutdown function.
    """
    name = "Unknown"
    dep_list = list()
    base = None
    passed = False

    def __init__(self, test_obj, test_base):
        self.name = str(test_obj)
        print "Init context for test: " + self.name
        self.base = test_base
        if self.base is None:
            raise Exception("Test base can not be None for test: " +
                            self.name)
        self.base.add_test(self.name, self)

    def add_dependent_test(self, test_obj):
        test_name = str(test_obj)
        print "Making test " + test_name + " depend on context of " + self.name
        print "Base: " + str(self.base)
        t = self.base.get_test_context(test_name)
        if t is None:
            raise Exception("Unknown dependent test: " + test_name)
        if t.check_is_dependent(self.name):
            raise Exception("Interdependency are not allowed: [" +
                            test_name + ", " + self.name + "]")
        self.dep_list.append(test_name)

    def get_dep_test_context(self, test_obj):
        test_name = str(test_obj)
        if test_name not in self.dep_list:
            raise Exception("Can not get dependent test context. Test " +
                            self.name + " does not depend on: " + test_name)
        return self.base.get_test_context(test_name)

    def check_is_dependent(self, test_obj):
        test_name = str(test_obj)
        for t in self.dep_list:
            if t == test_name:
                return True
        return False

    def shutdown(self):
        print "Shutting down test " + self.name
        for t in self.dep_list:
            self.base.delete_test(t)
        self._shutdown_()

    def _run_(self, conf):
        """
        Replaced by a real test.
        """

    def run(self, conf):
        print "Starting test: " + self.name
        try:
            self._run_(conf)
        except:
            print "Test " + self.name + " finished with exception"
            traceback.print_exc()
        finally:
            print "Test " + self.name + " is done"

    def _shutdown_(self):
        """
        Replaced by a real test function
        """