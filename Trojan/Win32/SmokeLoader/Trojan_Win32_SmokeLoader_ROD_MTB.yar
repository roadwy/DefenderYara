
rule Trojan_Win32_SmokeLoader_ROD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ROD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 70 8b 45 70 03 85 0c ff ff ff 8d 14 3b 33 c2 33 c1 29 85 18 ff ff ff 8b 85 18 ff ff ff c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}