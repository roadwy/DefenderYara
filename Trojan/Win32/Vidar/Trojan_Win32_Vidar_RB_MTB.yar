
rule Trojan_Win32_Vidar_RB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 10 75 08 8b 45 88 88 0c 38 eb 0a 8a 00 32 c1 8b 4d 88 88 04 39 ff 75 90 ff 45 94 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 8a 0a 0f b6 d9 8d 84 85 90 01 02 ff ff 39 18 75 08 8b 45 fc 88 0c 10 eb 0a 8a 00 32 c1 8b 4d fc 88 04 11 ff 45 f8 90 00 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}
rule Trojan_Win32_Vidar_RB_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 68 c0 41 c8 17 6a 00 ff 15 } //1
		$a_01_1 = {0f a2 89 06 89 5e 04 89 4e 08 89 56 0c 6a 01 ff d7 6a 01 ff d7 6a 01 ff d7 6a 01 ff d7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}