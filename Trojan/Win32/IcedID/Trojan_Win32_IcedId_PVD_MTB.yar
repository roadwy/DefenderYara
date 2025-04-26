
rule Trojan_Win32_IcedId_PVD_MTB{
	meta:
		description = "Trojan:Win32/IcedId.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c3 89 2d ?? ?? ?? ?? 8b e8 2b ee 8d 34 29 81 c2 b4 33 da 01 8d 0c c0 2b 0d ?? ?? ?? ?? 89 17 90 09 07 00 8b 17 a3 } //2
		$a_00_1 = {8a 9c 24 df 03 00 00 88 a4 24 7f 01 00 00 c7 84 24 ec 00 00 00 00 00 00 00 c7 84 24 e8 00 00 00 46 3e 00 00 80 f3 16 c6 84 24 97 01 00 00 94 88 9c 24 0f 01 00 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}