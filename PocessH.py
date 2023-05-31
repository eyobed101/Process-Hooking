import ctypes
import logging

class ProcessProxy:

    def __init__(self, process_id):
        self.process_id = process_id
        self.original_functions = {}

    def hook_function(self, function_name):
        original_function = ctypes.cdll.LoadLibrary("kernel32.dll").GetProcAddress(None, function_name)
        self.original_functions[function_name] = original_function

        def hooked_function(*args):
            logging.info("Intercepting call to %s", function_name)
            result = original_function(*args)
            logging.info("Returning from %s", function_name)
            return result

        ctypes.cdll.LoadLibrary("kernel32.dll").SetProcAddress(None, function_name, hooked_function)

    def unhook_function(self, function_name):
        ctypes.cdll.LoadLibrary("kernel32.dll").SetProcAddress(None, function_name, self.original_functions[function_name])

    def start(self):
        self.hook_function("CreateFileW")
        self.hook_function("ReadFile")
        self.hook_function("WriteFile")

    def stop(self):
        self.unhook_function("CreateFileW")
        self.unhook_function("ReadFile")
        self.unhook_function("WriteFile")