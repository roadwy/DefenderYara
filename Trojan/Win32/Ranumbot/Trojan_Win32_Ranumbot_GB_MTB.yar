
rule Trojan_Win32_Ranumbot_GB_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 f6 39 1d 90 01 04 76 90 01 01 81 3d 90 01 08 a1 90 01 04 8a 84 30 90 01 04 8b 0d 90 01 04 88 04 31 90 18 46 3b 35 90 01 04 72 90 01 01 e8 90 01 04 e8 90 01 04 33 f6 90 00 } //0a 00 
		$a_02_1 = {51 6a 40 ff 35 90 01 04 a3 90 01 04 ff 35 90 01 04 ff d0 46 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 14 8b 90 01 01 c1 e9 90 01 01 89 4c 24 10 8b 44 24 90 01 01 01 44 24 10 8b f7 c1 e6 90 01 01 03 74 24 90 01 01 8d 14 2f 33 f2 81 3d 90 01 08 c7 05 90 01 08 90 18 31 74 24 10 81 3d 90 00 } //0a 00 
		$a_02_1 = {8b 4c 24 10 33 cb 33 ce 8d 44 24 14 e8 90 01 04 81 3d 90 01 08 90 18 81 c5 90 01 04 83 6c 24 18 01 0f 85 90 01 04 8b 84 24 90 01 04 8b 54 24 14 89 78 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}