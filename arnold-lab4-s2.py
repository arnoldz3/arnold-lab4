## ***********************************************************************************************
## 
##       filename:  arnold-lab4-s2.py
## 
##    description:  Searches an IDA database for any occurences of certain standard C library
##                  functions.
## 
##         author:  Arnold, Zackery
## 
##          class:  CPS 473
##     instructor:  Deep
##     assignment:  Lab 4
## 
##       assigned:  March 20, 2017
##            due:  March 27, 2017
## 
## ***********************************************************************************************

def FindFunctions(func_list):
    # This loop will look for any functions called from a given
    # address. It will walk through the code of a given function
    # line by line, tracing function calls that branch from the
    # given control path.
    n = len(func_list)
    funcs_found = [False for i in range(n)]
    checked = []
 
    # We will only ever explore the .text section.
    for seg in Segments():
    
        if(SegName(seg) == ".text"):
            for addr in range(seg, SegEnd(seg)):

                if isCode(GetFlags(addr)):
                    # Get the mnemonic and increment the count
                    mnem = GetMnem(addr)
                    if mnem == 'call' or mnem == 'jmp':
                        name = GetFunctionName(addr)
                        if (name == ""):
                            name = "[N/A]"
                        # Call and JMP take a single argument in the form of an address.
                        # IDA gives a visual text based representation for this argument.
                        # This can be parsed for the correct occurences of library calls.
                        op = GetOpnd(addr, 0)
                        # Iterate through the function names to check search status.
                        for i in range(0, n):
                            if (op.find(func_list[i]) > -1):
                                print name, ':', hex(addr), ":", func_list[i]
                                funcs_found[i] = True

    if(not any(funcs_found)):
        print "None of the functions", func_list, "were called in the program."
        return 
    
def main():
    func_list = ["strcpy", "sprintf", "strncpy", "wcsncpy", "swprintf"]
    address = MinEA()
    FindFunctions(func_list)

main()