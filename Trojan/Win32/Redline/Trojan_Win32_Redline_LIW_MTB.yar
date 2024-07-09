
rule Trojan_Win32_Redline_LIW_MTB{
	meta:
		description = "Trojan:Win32/Redline.LIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 8b 4c 24 24 8d 44 24 1c c7 05 ?? ?? ?? ?? ee 3d ea f4 89 54 24 1c e8 ?? ?? ?? ?? 8b 44 24 28 31 44 24 10 81 3d ?? ?? ?? ?? e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 10 31 44 24 1c 81 3d ?? ?? ?? ?? 13 02 00 00 75 } //1
		$a_03_1 = {29 44 24 14 83 6c 24 14 64 8b 44 24 14 8d 4c 24 10 e8 ?? ?? ?? ?? 8b 44 24 2c 01 44 24 10 8b 44 24 14 8b 4c 24 18 8d 14 03 31 54 24 10 d3 e8 03 44 24 30 81 3d ?? ?? ?? ?? 21 01 00 00 8b f8 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}