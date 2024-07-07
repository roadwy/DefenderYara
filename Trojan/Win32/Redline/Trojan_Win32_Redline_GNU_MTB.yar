
rule Trojan_Win32_Redline_GNU_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 06 59 59 0f b6 0f 03 c8 0f b6 c1 8b 4c 24 90 01 01 8a 84 04 90 01 04 30 85 90 01 04 45 81 fd 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNU_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 1f 90 01 01 68 90 01 04 68 90 01 04 e8 90 01 04 50 e8 90 01 04 80 04 1f 90 01 01 83 c4 40 68 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNU_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 f0 56 57 e8 90 01 04 0f b6 06 83 c4 90 01 01 0f b6 0f 03 c8 0f b6 c1 8b 4c 24 90 01 01 8a 84 04 90 01 04 30 85 90 01 04 45 81 fd 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}