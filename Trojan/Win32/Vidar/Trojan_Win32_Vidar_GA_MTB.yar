
rule Trojan_Win32_Vidar_GA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 8b 0d 90 01 04 8a 94 01 90 01 04 8b 0d 90 01 04 88 14 01 83 c4 90 01 01 c3 90 00 } //0a 00 
		$a_02_1 = {8b d3 c1 ea 90 01 01 8d 0c 18 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b f3 c1 e6 04 03 74 24 90 01 01 c7 05 90 01 08 33 f1 81 3d 90 01 08 90 18 31 74 24 90 01 01 81 3d 90 00 } //0a 00 
		$a_02_2 = {89 44 24 10 8b 44 24 90 01 01 01 44 24 90 01 01 81 3d 90 01 08 90 18 8b 4c 24 10 33 cf 33 ce 2b d9 81 3d 90 01 08 90 18 8b 44 24 90 01 01 29 44 24 90 01 01 83 6c 24 90 01 01 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Vidar_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.GA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c3 f7 75 08 8b 45 0c 8d 0c 33 8a 04 02 8b 55 fc 32 04 0a 43 88 01 3b df 72 } //00 00 
	condition:
		any of ($a_*)
 
}