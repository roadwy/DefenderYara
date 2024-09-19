
rule Trojan_Win32_GCleaner_KGF_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.KGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8b 44 24 1c c1 e8 05 89 44 24 18 8b 44 24 18 03 44 24 3c 33 ca 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 18 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}