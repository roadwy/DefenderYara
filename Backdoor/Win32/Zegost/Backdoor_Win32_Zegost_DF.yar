
rule Backdoor_Win32_Zegost_DF{
	meta:
		description = "Backdoor:Win32/Zegost.DF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c6 8a 44 45 e4 30 01 46 42 3b d7 72 } //1
		$a_01_1 = {c6 45 f7 48 c6 45 f8 49 c6 45 f9 44 c6 45 fa 45 c6 45 fb 55 c6 45 fc 52 c6 45 fd 4c } //1
		$a_01_2 = {5c 5c 2e 5c 61 67 6d 6b 69 73 32 } //1 \\.\agmkis2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}