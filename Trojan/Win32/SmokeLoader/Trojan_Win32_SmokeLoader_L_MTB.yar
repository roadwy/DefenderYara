
rule Trojan_Win32_SmokeLoader_L_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea 03 c7 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 dc 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec 75 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}