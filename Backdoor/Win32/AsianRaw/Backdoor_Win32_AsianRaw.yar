
rule Backdoor_Win32_AsianRaw{
	meta:
		description = "Backdoor:Win32/AsianRaw,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 73 69 61 6e 72 61 77 2e 63 6f 6d 2f 6d 65 6d 62 65 72 73 2f 76 73 2e 68 74 6d 6c } //1 http://www.asianraw.com/members/vs.html
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 72 69 74 69 73 68 74 6f 74 74 79 2e 63 6f 6d 2f 63 6f 6e 74 65 6e 74 2f 68 6f 6d 65 70 61 67 65 2e 68 74 6d 6c } //1 http://www.britishtotty.com/content/homepage.html
		$a_01_2 = {54 45 58 54 5f 45 4e 47 4c 49 53 48 } //3 TEXT_ENGLISH
		$a_01_3 = {52 61 73 48 61 6e 67 55 70 41 } //10 RasHangUpA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*10) >=14
 
}