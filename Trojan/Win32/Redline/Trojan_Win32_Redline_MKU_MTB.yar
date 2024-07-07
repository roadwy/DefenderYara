
rule Trojan_Win32_Redline_MKU_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 08 0f be 4d 90 01 01 31 c8 0f be 4d 90 01 01 01 c8 88 c2 8b 45 90 01 01 8b 4d 90 01 01 88 14 08 0f be 75 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 0f be 14 08 29 f2 88 14 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MKU_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea c7 05 90 01 08 03 54 24 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 83 3d 90 01 05 75 90 00 } //1
		$a_03_1 = {d3 e2 8b 4c 24 90 01 01 03 c8 c1 e8 90 01 01 03 d5 89 54 24 90 01 01 89 4c 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 54 24 90 01 01 33 54 24 90 01 01 8b 44 24 90 01 01 33 c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}