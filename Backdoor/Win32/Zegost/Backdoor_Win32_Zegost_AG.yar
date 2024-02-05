
rule Backdoor_Win32_Zegost_AG{
	meta:
		description = "Backdoor:Win32/Zegost.AG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 3b 47 65 74 50 75 90 01 01 81 7b 04 72 6f 63 41 75 90 01 01 60 8b 75 fc 8b 5e 24 90 00 } //01 00 
		$a_03_1 = {b9 00 08 00 00 33 c0 8d bd 00 e0 ff ff f3 ab 6a 00 68 00 20 00 00 8d 8d 00 e0 ff ff 51 8b 95 90 01 02 ff ff 8b 82 90 01 01 00 00 00 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}