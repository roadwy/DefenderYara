
rule Trojan_Win32_GCleaner_AZZ_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 70 8b 45 70 8b 8d c8 fe ff ff 03 c7 03 cb 33 c1 33 c6 29 85 c0 fe ff ff 8b 85 c0 fe ff ff c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}