
rule Trojan_Win32_Vidar_GA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 45 f8 33 d2 f7 f1 8b 45 0c 8a 0c 02 8b 45 f0 8b 55 08 32 0c 02 88 08 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Vidar_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01 83 c4 ?? c3 } //10
		$a_02_1 = {8b d3 c1 ea ?? 8d 0c 18 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 04 03 74 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 f1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 90 18 31 74 24 ?? 81 3d } //10
		$a_02_2 = {89 44 24 10 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 90 18 8b 4c 24 10 33 cf 33 ce 2b d9 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 90 18 8b 44 24 ?? 29 44 24 ?? 83 6c 24 ?? 01 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10) >=20
 
}
rule Trojan_Win32_Vidar_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.GA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c3 f7 75 08 8b 45 0c 8d 0c 33 8a 04 02 8b 55 fc 32 04 0a 43 88 01 3b df 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Vidar.GA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 45 f8 8b 4d f0 8d 14 01 8b 4d f4 31 55 fc 8b f0 d3 ee } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}