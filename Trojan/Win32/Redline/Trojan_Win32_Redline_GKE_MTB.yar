
rule Trojan_Win32_Redline_GKE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 2f 90 01 01 47 e2 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GKE_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 c2 f6 d0 32 c2 2a c8 8a c2 80 f1 90 01 01 02 c0 02 ca 32 ca 80 f1 90 01 01 2a c8 fe c1 32 ca 88 4c 14 90 01 01 42 83 fa 0f 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}