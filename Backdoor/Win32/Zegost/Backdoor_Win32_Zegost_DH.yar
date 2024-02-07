
rule Backdoor_Win32_Zegost_DH{
	meta:
		description = "Backdoor:Win32/Zegost.DH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 81 ac 00 00 00 c6 45 90 01 01 47 c6 45 90 01 01 68 c6 45 90 01 01 30 c6 45 90 01 01 73 8b 90 00 } //01 00 
		$a_03_1 = {8a 14 01 80 c2 90 01 01 80 f2 90 01 01 88 14 01 90 02 03 3b ce 7c 90 00 } //01 00 
		$a_01_2 = {0d 0a 3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e 00 } //00 00 
		$a_00_3 = {78 6c } //00 00  xl
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Zegost_DH_2{
	meta:
		description = "Backdoor:Win32/Zegost.DH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 90 01 01 88 10 83 c0 01 83 90 01 03 01 75 ee 90 00 } //02 00 
		$a_03_1 = {c7 86 a8 00 00 00 ff ff ff ff c6 45 90 01 01 47 c6 45 90 01 01 68 c6 45 90 01 01 30 c6 45 90 01 01 73 b3 74 90 00 } //01 00 
		$a_01_2 = {0d 0a 3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}