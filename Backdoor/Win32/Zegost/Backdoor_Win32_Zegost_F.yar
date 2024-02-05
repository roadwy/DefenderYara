
rule Backdoor_Win32_Zegost_F{
	meta:
		description = "Backdoor:Win32/Zegost.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 68 63 70 63 73 76 63 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {c7 44 24 34 18 00 00 00 c7 44 24 3c 01 00 01 70 c7 44 24 40 01 00 00 00 c7 44 24 44 94 00 00 00 } //01 00 
		$a_03_2 = {89 86 f4 00 00 00 c7 86 c0 00 00 00 20 00 cc 00 c6 86 b4 00 00 00 01 ff 15 90 01 04 8b 4c 24 6c 89 86 c4 00 00 00 b8 e8 03 00 00 33 d2 f7 f1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}