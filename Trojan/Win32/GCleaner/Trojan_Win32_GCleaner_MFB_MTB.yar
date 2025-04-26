
rule Trojan_Win32_GCleaner_MFB_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.MFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 07 8b 44 24 18 c1 e8 05 89 44 24 10 8b 44 24 10 33 ca 03 c5 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 10 0f 85 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}