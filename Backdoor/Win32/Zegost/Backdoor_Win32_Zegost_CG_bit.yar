
rule Backdoor_Win32_Zegost_CG_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 08 8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //01 00 
		$a_03_1 = {4b c6 44 24 90 01 01 52 c6 44 24 90 01 01 4e c6 44 24 90 01 01 4c c6 44 24 90 01 01 33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e c6 44 24 90 01 01 64 90 00 } //01 00 
		$a_03_2 = {8a 14 08 80 c2 90 01 01 88 14 08 8b 4c 24 08 8a 14 08 80 f2 90 01 01 88 14 08 40 3b c6 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}