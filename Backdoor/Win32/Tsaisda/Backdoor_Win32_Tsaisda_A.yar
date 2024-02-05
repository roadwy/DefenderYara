
rule Backdoor_Win32_Tsaisda_A{
	meta:
		description = "Backdoor:Win32/Tsaisda.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c2 f8 3b 90 01 01 76 29 90 01 05 81 3c 01 90 01 04 75 06 39 90 01 01 01 04 74 07 41 3b ca 72 ec eb 0e 03 c8 90 00 } //01 00 
		$a_03_1 = {75 49 33 f6 bf 90 01 04 68 90 01 04 ff 15 90 01 04 8d 44 24 08 c7 05 90 01 08 50 6a 00 68 90 01 04 ff 15 90 01 04 85 c0 74 17 6a 01 ff 15 90 01 04 46 89 3d 90 01 04 81 fe 10 27 00 00 7c be 90 00 } //01 00 
		$a_03_2 = {51 68 a0 0f 00 00 52 55 ff 15 90 01 04 85 c0 74 2e 8b 44 24 10 85 c0 74 1f 8d 4c 24 14 6a 00 51 8d 94 24 90 01 04 50 52 56 ff 15 90 01 04 89 3d 90 01 04 eb bc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}