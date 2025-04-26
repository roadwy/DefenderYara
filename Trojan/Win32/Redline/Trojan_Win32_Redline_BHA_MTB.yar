
rule Trojan_Win32_Redline_BHA_MTB{
	meta:
		description = "Trojan:Win32/Redline.BHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 8b 4d e4 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f0 8d 45 f0 e8 ?? ?? ?? ?? 8b 45 e0 31 45 fc 81 3d ?? ?? ?? ?? e6 09 00 00 75 } //1
		$a_03_1 = {8b 45 dc 01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 8d 34 17 81 c7 ?? ?? ?? ?? 03 45 d8 33 c6 31 45 fc 2b 5d fc ff 4d ec 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}