
rule Trojan_Win32_Redline_GKK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3c 90 01 04 03 c6 59 8b 4c 24 90 01 01 0f b6 c0 8a 84 04 90 01 04 30 81 90 01 04 41 89 4c 24 90 01 01 81 f9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GKK_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e7 89 c8 29 d0 d1 e8 01 d0 c1 e8 90 01 01 6b c0 90 01 01 01 c8 c1 e8 90 01 01 0f be 80 90 01 04 69 c0 90 01 04 89 c2 c1 ea 90 01 01 c1 e8 90 01 01 01 d0 c0 e0 90 01 01 30 84 0e 90 01 04 83 c1 90 01 01 81 f9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}