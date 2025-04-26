
rule Trojan_Win32_Redline_CTI_MTB{
	meta:
		description = "Trojan:Win32/Redline.CTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e0 04 03 44 24 30 8d 34 0b c1 e9 05 83 3d ?? ?? ?? ?? 1b 89 44 24 14 8b e9 75 10 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 14 03 6c 24 28 c7 05 ?? ?? ?? ?? 00 00 00 00 33 ee 33 e8 2b fd 8b d7 c1 e2 04 89 54 24 14 8b 44 24 20 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 2c 3b 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}