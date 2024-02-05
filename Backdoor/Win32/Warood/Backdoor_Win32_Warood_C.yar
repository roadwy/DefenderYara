
rule Backdoor_Win32_Warood_C{
	meta:
		description = "Backdoor:Win32/Warood.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 54 54 69 6d 65 00 } //01 00 
		$a_01_1 = {66 70 6c 6f 61 64 2e 64 6c 6c 00 } //01 00 
		$a_03_2 = {8b cd 4f c1 e9 02 f3 a5 8b cd 6a 01 83 e1 03 6a 01 f3 a4 50 ff 15 90 01 04 8b f0 8d 44 24 90 01 01 50 ff 15 90 01 04 85 c0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}