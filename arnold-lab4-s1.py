## ***********************************************************************************************
## 
##       filename:  arnold-lab4-s1.py
## 
##    description:  Searches an IDA database for any occurences of certain bytes
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

pattern = ['D76AA478', 'E8C7B756', '242070DB', 'C1BDCEEE']
addr = MinEA()
for x in range(0, len(pattern)):
    addr = FindBinary(addr, SEARCH_DOWN|SEARCH_NEXT, pattern[x]);
    if addr != BADADDR:
        print hex(addr), pattern[x], "MD5 Constants Detected"
    addr = MinEA()