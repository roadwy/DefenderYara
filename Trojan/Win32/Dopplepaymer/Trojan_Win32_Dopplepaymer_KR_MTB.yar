
rule Trojan_Win32_Dopplepaymer_KR_MTB{
	meta:
		description = "Trojan:Win32/Dopplepaymer.KR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 65 73 74 61 70 70 2e 65 78 65 } //1 testapp.exe
		$a_01_1 = {73 65 6c 66 2e 65 78 65 } //1 self.exe
		$a_01_2 = {54 00 45 00 53 00 54 00 41 00 50 00 50 00 2e 00 65 00 78 00 65 00 } //1 TESTAPP.exe
		$a_01_3 = {46 3a 5c 41 43 54 55 41 4c 4c 49 53 54 5c 4c 4f 47 49 4e 46 49 52 53 54 21 21 21 5c 40 52 54 47 57 45 48 57 2e 65 78 65 } //1 F:\ACTUALLIST\LOGINFIRST!!!\@RTGWEHW.exe
		$a_01_4 = {49 00 72 00 77 00 68 00 45 00 62 00 7a 00 65 00 68 00 2e 00 65 00 78 00 65 00 } //1 IrwhEbzeh.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}