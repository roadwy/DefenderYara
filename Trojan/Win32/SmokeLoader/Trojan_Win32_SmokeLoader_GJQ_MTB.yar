
rule Trojan_Win32_SmokeLoader_GJQ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 35 ?? ?? ?? ?? 03 55 d0 33 55 e8 33 d7 89 55 e8 8b 45 e8 } //10
		$a_03_1 = {d3 e8 8b 4d dc c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 e8 8d 45 e8 e8 ?? ?? ?? ?? 33 7d f0 31 7d e8 83 3d ?? ?? ?? ?? 1f } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}