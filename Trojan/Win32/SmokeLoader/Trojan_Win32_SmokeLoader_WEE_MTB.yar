
rule Trojan_Win32_SmokeLoader_WEE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.WEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c7 d3 ef 89 45 e4 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d d8 8b 45 e4 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 75 0b 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 2b df 83 3d ?? ?? ?? ?? 0c 75 } //1
		$a_03_1 = {8b 45 dc 01 45 fc 8b 4d f8 8b 45 f4 8b fb d3 ef 03 c3 31 45 fc 03 7d d4 81 3d ?? ?? ?? ?? 21 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}