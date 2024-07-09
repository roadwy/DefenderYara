
rule Trojan_Win32_SmokeLoader_RDD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 84 30 3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 7a 06 00 00 75 08 53 53 } //2
		$a_03_1 = {8b c7 d3 e8 89 45 fc 8b 45 cc 01 45 fc 8b 45 fc 33 45 e8 83 25 ?? ?? ?? ?? 00 31 45 f8 2b 5d f8 81 45 e4 ?? ?? ?? ?? ff 4d dc 89 5d e0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}