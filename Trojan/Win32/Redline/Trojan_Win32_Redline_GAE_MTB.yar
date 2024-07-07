
rule Trojan_Win32_Redline_GAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 89 54 24 1c 8b c1 c1 e8 18 33 c1 69 c8 90 01 04 69 c7 90 01 04 33 c8 8b 44 24 2c 8b f9 3b d0 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GAE_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 1c 33 8b c6 8b 4c 24 18 f7 75 08 83 c4 0c 8a 82 90 01 04 ba 90 01 04 32 c3 88 44 24 13 02 c3 88 04 31 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}