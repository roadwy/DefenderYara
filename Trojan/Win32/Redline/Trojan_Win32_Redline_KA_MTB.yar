
rule Trojan_Win32_Redline_KA_MTB{
	meta:
		description = "Trojan:Win32/Redline.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 c7 33 45 c8 88 45 c7 0f b6 4d c7 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_KA_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 89 35 90 01 04 8b 45 90 01 01 29 45 90 01 01 8d 45 90 01 01 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_KA_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 89 35 90 01 04 8b 45 90 01 01 29 45 90 01 01 81 45 e0 90 01 04 ff 4d 90 01 01 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}