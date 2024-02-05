
rule Backdoor_Win32_Tofsee_BD_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f7 c1 ee 05 03 74 24 90 01 01 03 90 01 01 03 90 01 01 33 90 01 01 81 3d 90 01 04 72 07 00 00 75 90 09 1b 00 56 ff 15 90 01 04 8b 90 01 01 24 90 01 01 8b 90 01 01 24 90 01 01 89 35 90 01 04 89 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Tofsee_BD_MTB_2{
	meta:
		description = "Backdoor:Win32/Tofsee.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c1 03 05 90 01 04 25 ff 00 00 00 8a 90 01 05 88 88 90 01 04 88 96 90 01 04 0f b6 b0 90 01 04 0f b6 ca 03 f1 81 e6 ff 00 00 00 81 3d 90 01 04 81 0c 00 00 90 00 } //01 00 
		$a_02_1 = {30 06 83 6c 24 90 01 01 01 8b 44 24 90 01 01 85 c0 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}