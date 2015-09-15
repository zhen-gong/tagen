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
        #for t in self.dep_base.keys():
        #    print str(t) + ": " + str(self.dep_base[t])
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
    description = "Unknown description"
    dependents = None
    depend_on = None
    base = None
    passed = False
    test_obj = None


    def __init__(self, test_obj, test_base):
        self.test_obj = test_obj
        self.name = str(test_obj)
        print "Init context for test: " + self.name
        self.base = test_base
        if self.base is None:
            raise Exception("Test base can not be None for test: " +
                            self.name)
        self.base.add_test(self.name, self)
        self.depend_on = list()

    def add_as_dependent_on(self, test_obj):
        test_name = str(test_obj)
        print "Making test " + self.name + " depend on context of " + test_name
        t = self.base.get_test_context(test_name)
        if t is None:
            raise Exception("Unknown dependent test: " + test_name)
        if self.check_is_dependent_of(test_obj):
            raise Exception("Interdependency are not allowed: [" +
                            test_name + ", " + self.name + "]")
        t._add_dependent(self.test_obj)
        self.depend_on.append(test_name)

    def _add_dependent(self, test_obj):
        test_name = str(test_obj)
        if self.dependents is None:
            self.dependents = list()
        self.dependents.append(test_name)

    def get_dep_test_context(self, test_obj):
        test_name = str(test_obj)
        if test_name not in self.depend_on:
            raise Exception("Can not get dependent test context. Test " +
                            self.name + " does not depend on: " + test_name)
        return self.base.get_test_context(test_name)

    def set_passed(self):
        self.passed = True

    def get_status(self):
        return self.passed

    def check_is_dependent_of(self, test_obj):
        test_name = str(test_obj)
        for t in self.depend_on:
            if t == test_name:
                return True
        return False

    def print_dependents(self):
        print "List of dependent tests(" + str(self) + "); obj: " + str(self.dependents)

    def shutdown(self):
        print ">> Shutting down test " + self.name
        if self.dependents is not None:
            for t in self.dependents:
                self.base.delete_test(t)
        self._shutdown_()
        print "<< Shutting down test " + self.name

    def _run_(self, conf):
        """
        Replaced by a real test.
        """

    def run(self, conf):
        print "------------------"
        print "==>>> Starting test: " + self.name
        print "Description: " + self._get_description_()
        try:
            self._run_(conf)
        except:
            print "vvv! Test " + self.name + " finished with exception !vvv"
            traceback.print_exc()
            print "^^^^^^"
        finally:
            print "<<<== Test " + self.name + " is done"

    def _shutdown_(self):
        """
        Replaced by a real test function
        """

    def _get_description_(self):
        """
        Replaced by a real test function
        """
        return "Description Unknown"
