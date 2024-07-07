
rule Trojan_Win32_Zenpak_GJN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e0 50 8f 05 90 01 04 eb 90 01 01 42 42 83 c0 07 8d 05 90 01 04 31 28 e8 90 01 04 c3 48 48 29 c2 31 35 90 01 04 83 e8 01 40 01 1d 90 01 04 31 c2 31 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}