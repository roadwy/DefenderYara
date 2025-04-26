
rule Trojan_Win32_Redline_MKU_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 08 0f be 4d ?? 31 c8 0f be 4d ?? 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f be 14 08 29 f2 88 14 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MKU_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 54 24 ?? 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 83 3d ?? ?? ?? ?? ?? 75 } //1
		$a_03_1 = {d3 e2 8b 4c 24 ?? 03 c8 c1 e8 ?? 03 d5 89 54 24 ?? 89 4c 24 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 33 54 24 ?? 8b 44 24 ?? 33 c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}