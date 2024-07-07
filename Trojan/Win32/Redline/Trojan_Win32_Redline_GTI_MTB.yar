
rule Trojan_Win32_Redline_GTI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 50 e8 90 01 04 33 d2 8a 1c 33 8b c6 8b 4c 24 18 f7 75 08 83 c4 0c 8a 82 90 01 04 32 c3 88 44 24 90 01 01 02 c3 88 04 31 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GTI_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea 8d 04 0a c1 f8 90 01 01 89 c2 89 c8 c1 f8 90 01 01 29 c2 89 d0 ba 90 01 04 0f af c2 89 c1 8b 55 90 01 01 8b 45 90 01 01 01 d0 31 cb 89 da 88 10 83 45 ec 01 eb 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}