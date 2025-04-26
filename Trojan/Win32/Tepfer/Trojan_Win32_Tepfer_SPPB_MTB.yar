
rule Trojan_Win32_Tepfer_SPPB_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.SPPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 33 c2 33 45 74 c7 05 ?? ?? ?? ?? ee 3d ea f4 2b c8 89 45 70 8b c1 c1 e0 04 89 45 74 8b 85 ?? ?? ?? ?? 01 45 74 8b c1 c1 e8 05 89 45 70 8b 85 ?? ?? ?? ?? 01 45 70 8d 04 0e 33 45 70 31 45 74 8b 45 74 29 45 6c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}