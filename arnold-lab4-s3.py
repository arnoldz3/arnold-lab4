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

exp_list = []
checked = []

def isBelowExport(addr, exp_list, checked):

    # This loop will look for any functions called from a given
    # address. It will walk through the code of a given function
    # line by line, tracing function calls that branch from the
    # given control path.
    last_ref = addr

    for refs in CodeRefsFrom(addr, 1):
        if refs in checked:
            continue
        checked.append(refs)
        if isCode(GetFlags(refs)):
            # Get the mnemonic and increment the count
            mnem = GetMnem(refs)
            if mnem == 'call' or mnem == 'jmp':

                # Call and JMP take a single argument in the form of an address.
                # IDA gives a visual text based representation for this argument.
                # This can be parsed for the correct occurences of library calls.
                name = GetFunctionName(refs)
                if (name == ""):
                    name = "[N/A]"
                op = GetOpnd(refs, 0)
                if (op.find("strcpy") > -1):
                    print exp_list, ':', hex(refs), ":", "strcpy"
                if (op.find("sprintf") > -1):
                    print exp_list, ':', hex(refs), ":", "sprintf"
                if (op.find("strncpy") > -1):
                    print exp_list, ':', hex(refs), ":", "strncpy"
                if (op.find("wcsncpy") > -1):
                    print exp_list, ':', hex(refs), ":", "wcsncpy"
                if (op.find("swprintf") > -1):
                    print exp_list, ':', hex(refs), ":", "swprintf"

        # If this refference is linear, don't bother with recursion.
        isBelowExport(refs, exp_list, checked)

## Must start from the export list. They can be found as follows:
for i in range(GetEntryPointQty()):
    ord = GetEntryOrdinal(i)
    if ord == 0:
        continue
    addr = GetEntryPoint(ord)
    exp_list.append(GetFunctionName(addr))
    isBelowExport(addr, exp_list[i], checked)