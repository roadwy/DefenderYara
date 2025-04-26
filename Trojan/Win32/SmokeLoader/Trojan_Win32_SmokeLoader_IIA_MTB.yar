
rule Trojan_Win32_SmokeLoader_IIA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.IIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 70 8b 45 70 03 85 10 ff ff ff 8b 95 ?? ?? ?? ?? 03 d7 33 c2 33 c1 2b d8 8b c3 c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 8b 85 0c ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}