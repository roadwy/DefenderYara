
rule PWS_Win32_Frethog_BY{
	meta:
		description = "PWS:Win32/Frethog.BY,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 } //01 00 
		$a_01_1 = {51 54 6a 01 6a 00 68 e1 fa ed 0e } //01 00 
		$a_03_2 = {8b d8 6a 32 8d 45 90 01 01 50 53 e8 90 01 02 ff ff 8d 4d fc 90 00 } //03 00 
		$a_03_3 = {7e 1e bf 01 00 00 00 8b 5d fc 8b 45 f8 e8 90 01 03 ff 8a 13 80 f2 90 01 01 88 54 38 ff 47 43 4e 75 ea 90 00 } //03 00 
		$a_03_4 = {8b 45 f0 80 7c 18 fa e8 75 90 01 01 8b 45 f0 80 7c 18 f2 c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}