
rule Trojan_Win32_Zenpak_GZN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4a 31 d0 40 8d 05 90 01 04 01 20 83 f2 01 e8 90 01 04 ba 90 01 04 8d 05 90 01 04 01 18 8d 05 90 01 04 ff e0 8d 05 90 01 04 89 30 89 d0 8d 05 90 01 04 01 28 40 8d 05 90 01 04 31 38 b9 02 00 00 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}