
rule PWS_Win32_QQpass_CJQ{
	meta:
		description = "PWS:Win32/QQpass.CJQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1 } //1
		$a_00_1 = {68 74 74 70 3a 2f 2f 32 30 31 31 71 77 2e 71 71 62 79 2e 6f 72 67 2f } //1 http://2011qw.qqby.org/
		$a_00_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 51 51 2e 65 78 65 } //1 taskkill /f /im QQ.exe
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}