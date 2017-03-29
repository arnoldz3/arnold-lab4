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

## Parse through the database here....
for seg in Segments():
    # For each of the defined elements
    for line in range(seg, SegEnd(seg)):
        # If it's an instruction
        if isCode(GetFlags(line)):
            # Get the mnemonic and increment the count
            mnem = GetMnem(line)
            if mnem == 'call' or mnem == 'jmp':

                # Call and JMP take a single argument in the form of an address.
                # IDA gives a visual text based representation for this argument.
                # This can be parsed for the correct occurences of library calls.
                name = GetFunctionName(line)
                if (name == ""):
                    name = "[N/A]"
                op = GetOpnd(line, 0)
                # print op
                if (op.find("strcpy") > -1):
                    print name, ':', hex(line), ":", "strcpy"
                if (op.find("sprintf") > -1):
                    print name, ':', hex(line), ":", "sprintf"
                if (op.find("strncpy") > -1):
                    print name, ':', hex(line), ":", "strncpy"
                if (op.find("wcsncpy") > -1):
                    print name, ':', hex(line), ":", "wcsncpy"
                if (op.find("swprintf") > -1):
                    print name, ':', hex(line), ":", "swprintf"