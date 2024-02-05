
rule Backdoor_Win32_Zegost_CJ_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 08 32 4d 90 01 01 02 4d 90 01 01 88 08 b8 90 01 03 00 c3 90 00 } //01 00 
		$a_03_1 = {8b 45 08 8b 78 3c 03 f8 81 3f 50 45 00 00 75 34 8b 35 90 01 03 00 6a 04 68 00 20 00 00 ff 77 90 01 01 ff 77 90 01 01 ff d6 90 00 } //01 00 
		$a_01_2 = {53 68 65 6c 6c 65 78 00 } //00 00 
	condition:
		any of ($a_*)
 
}