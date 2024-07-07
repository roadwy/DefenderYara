
rule Trojan_Win32_Stelega_DP_MTB{
	meta:
		description = "Trojan:Win32/Stelega.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 08 8b 94 24 90 01 04 8b 4c 24 0c 2b d0 03 ca 89 8c 24 90 01 04 8b 4c 24 10 8b c2 d3 e8 89 94 24 90 01 04 89 44 24 08 8b 84 24 90 01 04 01 44 24 08 8b c2 c1 e0 04 03 84 24 90 01 04 33 84 24 90 01 04 81 3d 90 01 04 21 01 00 00 89 84 24 90 01 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}