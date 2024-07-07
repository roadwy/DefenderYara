
rule Trojan_Win32_Redline_GDT_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e0 03 b9 90 01 04 8a 98 90 01 04 32 9e 90 01 04 e8 90 01 04 89 85 90 01 04 8b 08 8b 49 04 8b 4c 01 30 8b 49 04 89 8d 90 01 04 8b 11 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GDT_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ea 6a 0e 07 c7 45 90 01 01 be 0f d6 65 c7 45 90 01 01 fe 8c 7d 37 c7 45 90 01 01 ee b1 e9 23 c7 45 90 01 01 e1 02 5b 54 c7 45 90 01 01 29 9f b2 1f c7 45 90 01 01 81 1a 44 62 c7 45 90 01 01 8f 1e cb 6e c7 45 90 01 01 cc af 7a 55 c7 45 90 01 01 53 72 3b 0b 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}