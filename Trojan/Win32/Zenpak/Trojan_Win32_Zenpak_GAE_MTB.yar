
rule Trojan_Win32_Zenpak_GAE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 01 c2 89 3d 90 01 04 8d 05 90 01 04 50 c3 29 d0 ba 90 01 04 29 c2 8d 05 90 01 04 31 28 83 e8 90 01 01 83 c0 90 01 01 31 1d 90 01 04 b9 02 00 00 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GAE_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c2 40 89 d8 50 8f 05 90 01 04 31 c2 b8 90 01 04 48 8d 05 90 01 04 89 38 40 48 8d 05 90 01 04 01 30 ba 90 01 04 83 f0 90 01 01 89 d0 89 2d 90 01 04 b9 02 00 00 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}