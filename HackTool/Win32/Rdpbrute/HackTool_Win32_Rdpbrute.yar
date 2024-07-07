
rule HackTool_Win32_Rdpbrute{
	meta:
		description = "HackTool:Win32/Rdpbrute,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 55 42 72 75 74 65 } //1 DUBrute
		$a_01_1 = {68 74 74 70 3a 2f 2f 75 62 72 75 74 65 2e 63 6f 6d } //1 http://ubrute.com
		$a_01_2 = {43 72 61 73 68 2e 2e 2e 20 25 73 3a 25 73 3a 25 73 } //1 Crash... %s:%s:%s
		$a_01_3 = {5b 50 61 73 73 77 6f 72 64 5d 0a 00 } //1
		$a_01_4 = {5b 4c 6f 67 69 6e 5d 0a 00 } //1
		$a_01_5 = {25 64 2e 25 64 2e 25 64 2e 25 64 2d 25 64 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}