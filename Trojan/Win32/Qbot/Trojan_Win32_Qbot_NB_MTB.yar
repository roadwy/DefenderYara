
rule Trojan_Win32_Qbot_NB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {33 55 f0 89 55 f0 8b 45 ec 8b 4d f8 d3 f8 83 f0 04 89 45 ec 8b 55 f4 03 55 08 8b 4d 08 d3 e2 8b 4d 08 d3 fa 8b 4d f8 d3 fa 8b 4d f8 d3 e2 8b 4d 08 d3 } //03 00 
		$a_81_1 = {72 6f 6c 6c 69 63 68 65 } //03 00 
		$a_81_2 = {74 72 69 6f 62 6f 6c } //03 00 
		$a_81_3 = {44 6c 6c 5c 6f 75 74 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_NB_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b7 f2 8d 90 02 03 89 90 02 05 8d 90 02 02 bf 90 02 04 2b fe 03 d7 0f 90 02 06 03 90 02 05 8b 90 02 03 89 90 02 05 8b 90 02 05 8d 90 02 06 8b 90 02 02 0f 90 02 02 39 90 02 05 90 18 83 90 02 04 8a c2 b3 11 f6 eb 81 90 02 05 02 c1 81 90 02 07 89 90 02 05 89 90 02 02 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}