
rule Trojan_Win32_Fauppod_MEA_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 d3 01 fb 8b 3b 69 d8 e8 00 00 00 01 da 81 c2 0a 00 00 00 0f b7 12 31 f2 8b b5 98 fe ff ff 01 ce 89 34 24 89 7c 24 04 } //3
		$a_03_1 = {8b 45 e0 8b 4d e4 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 dc 74 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}