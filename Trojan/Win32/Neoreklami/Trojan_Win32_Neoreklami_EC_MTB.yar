
rule Trojan_Win32_Neoreklami_EC_MTB{
	meta:
		description = "Trojan:Win32/Neoreklami.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 1e c1 fb 02 8b c3 d1 e8 2b d0 3b d3 73 04 33 db eb 02 03 d8 3b d9 0f 42 d9 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}