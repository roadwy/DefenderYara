
rule Trojan_Win32_Redline_BUM_MTB{
	meta:
		description = "Trojan:Win32/Redline.BUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d6 d3 ee 8b cb 8d 44 24 1c 89 54 24 2c 89 74 24 1c c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 e4 fe ff ff 8b 44 24 2c 31 44 24 0c 81 3d ?? ?? ?? ?? e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 0c 31 44 24 1c 81 3d ?? ?? ?? ?? 13 02 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}