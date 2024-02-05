
rule Backdoor_Win32_DriWrap_SD_MTB{
	meta:
		description = "Backdoor:Win32/DriWrap.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {54 41 49 4c 3a } //01 00 
		$a_81_1 = {4b 45 59 3a } //01 00 
		$a_03_2 = {56 57 8b fa 8b f1 8b cf e8 90 01 04 85 c0 75 90 01 01 81 90 02 06 75 90 00 } //01 00 
		$a_03_3 = {33 c9 2b d0 8d 90 01 02 33 90 01 01 0f b7 90 02 04 66 89 90 02 04 66 3b 90 01 01 74 90 02 08 41 3b 90 01 01 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}