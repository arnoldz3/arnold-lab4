// Examples from MSDN.
#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <cwchar>

void func() {

	int int1 = 0xd76aa478;
	int int2 = 0xe8c7b756;
	int int3 = 0x242070db;
	int int4 = 0xc1bdceee;

	char string1[80];
	strcpy(string1, "Hello world from "); // C4996  
										  // Note: strcpy is deprecated; use strcpy_s instead  
	strcat(string1, "strcpy ");           // C4996  
										  // Note: strcat is deprecated; use strcat_s instead  
	strcat(string1, "and ");              // C4996  
	strcat(string1, "strcat!");           // C4996  
	printf("String = %s\n", string1);

	char  buffer[200], s[] = "computer", c = 'l';
	int   i = 35, j;
	float fp = 1.7320534f;

	// Format and print various data:   
	j = sprintf(buffer, "   String:    %s\n", s); // C4996  

	char s2[20];

	// Note: strncpy is deprecated; consider using strncpy_s instead  
	strncpy(s2, "aa", 2);     // "aa BB CC"         C4996  

	wchar_t string2[100] = L"Cats are nice usually";
	printf("Before: %s\n", string2);
	wcsncpy(string2, L"Dogs", 4);
	printf("After:  %s\n", string2);

	wchar_t buf[100];
	int len = swprintf(buf, 100, L"%s", L"Hello world");
	printf("wrote %d characters\n", len);
}
int main() {

	func();
	return 0;
}

