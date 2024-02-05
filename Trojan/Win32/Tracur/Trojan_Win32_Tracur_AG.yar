
rule Trojan_Win32_Tracur_AG{
	meta:
		description = "Trojan:Win32/Tracur.AG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 2e 6a 70 67 74 1a 3d 2e 65 78 65 74 13 } //01 00 
		$a_03_1 = {0f a2 31 d0 31 c8 5a 31 c2 8b 45 90 01 01 8b 80 88 00 00 00 90 00 } //01 00 
		$a_01_2 = {e2 fa 5b 8b 45 08 8b 08 81 f9 14 e2 a4 fc 89 85 } //01 00 
		$a_01_3 = {66 3d 8b ff 74 14 31 c0 01 f8 05 00 02 00 00 3d 01 00 00 70 } //00 00 
	condition:
		any of ($a_*)
 
}