
rule Trojan_Win32_SmokeLoader_BBZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 70 8b 45 70 8b 95 80 fe ff ff 03 c7 03 d3 33 c2 33 c1 29 85 78 fe ff ff 8b 85 ?? ?? ?? ?? c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}