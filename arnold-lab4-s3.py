## ***********************************************************************************************
## 
##       filename:  arnold-lab4-s3.py
## 
##    description:  Searches an IDA database for any occurences of certain standard C library
##                  functions. Notes if those functions are below a given export function.
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
from collections import deque

def CollectExports():
    exp_list = []
    exp_addr = []
    for i in range(GetEntryPointQty()):
        ord = GetEntryOrdinal(i)
        if ord == 0:
            continue
        exp_addr.append(GetEntryPoint(ord))
        exp_list.append(GetFunctionName(addr))
    
    return exp_list, exp_addr

def isBelowExport(start, export, func_list):
    # This loop will look for any functions called from a given
    # address. It will walk through the code of a given function
    # line by line, tracing function calls that branch from the
    # given control path.
    n = len(func_list)
    funcs_found = [False for i in range(n)]
    addr_list = deque([start])
    checked = []
 
    while( addr_list ):
        # We have consumed an address, so pop it off the deque.
        addr = addr_list.popleft()
        
        # Collect all refferences from the
        # currently considered address.
        refs = CodeRefsFrom(addr, 1)

        # If there are no refferences to the code and there are no return addresses
        # then we will exit.
        if((refs == [] and len(addr_list) == 0) or (all(funcs_found))):
            if(not any(funcs_found)):
                print "None of the functions", func_list, "were called from within", export
            return
        
        # If only one reference returns, then it is the next line of code.
        # If more than one reference returns, then it means the line is a 
        # jump or a function call. The called function and the return address
        # are saved so that they can be iterated through.
        for i in range(0, len(refs)):
            # Only put up the address if we haven't been there before.
            if(not refs[i] in checked):
                addr_list.appendleft(refs[i])
                checked.append(refs[i])

        # Now we simply must look at the operands of the currently viewed
        # address and see if it contains the string we are looking for.
        if isCode(GetFlags(addr)):
            # Get the mnemonic and increment the count
            mnem = GetMnem(addr)
            if mnem == 'call' or mnem == 'jmp':
                #print GetDisasm(addr)
                # Call and JMP take a single argument in the form of an address.
                # IDA gives a visual text based representation for this argument.
                # This can be parsed for the correct occurences of library calls.
                op = GetOpnd(addr, 0)
                # Iterate through the function names to check search status.
                for i in range(0, n):
                    if (op.find(func_list[i]) > -1  and not funcs_found[i]):
                        print export, ':', hex(addr), ":", func_list[i]
                        funcs_found[i] = True

    print "Loop Exited.", export

def main():
    exports, addresses = CollectExports()
    func_list = ["strcpy", "sprintf", "strncpy", "wcsncpy", "swprintf"]
    for i in range(0, len(exports)):
        isBelowExport(addresses[i], exports[i],func_list)

main()