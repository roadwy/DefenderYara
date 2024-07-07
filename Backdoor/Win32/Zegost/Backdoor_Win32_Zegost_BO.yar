
rule Backdoor_Win32_Zegost_BO{
	meta:
		description = "Backdoor:Win32/Zegost.BO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {c6 45 f1 43 c6 45 f2 72 c6 45 f3 65 c6 45 f4 64 c6 45 f5 65 c6 45 f6 6e c6 45 f7 74 c6 45 f8 69 c6 45 f9 61 c6 45 fa 6c c6 45 fb 73 c6 45 fc 23 } //1
		$a_00_1 = {c6 45 e4 25 c6 45 e5 73 c6 45 e6 25 c6 45 e7 73 c6 45 e8 25 c6 45 e9 73 } //1
		$a_01_2 = {89 45 fc c6 45 f0 57 c6 45 f1 69 c6 45 f2 6e c6 45 f3 6c c6 45 f4 6f c6 45 f5 67 c6 45 f6 6f c6 45 f7 6e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}