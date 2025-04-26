
rule Trojan_Win32_SmokeLoader_Q_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4d f0 8b 4d f8 8b f3 d3 ee c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 dc 8b 45 f0 31 45 fc 81 3d ?? ?? ?? ?? e6 09 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}