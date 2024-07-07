
rule Trojan_Win64_Kegrelodr_B_MTB{
	meta:
		description = "Trojan:Win64/Kegrelodr.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d3 20 cb 30 ca 41 89 d8 41 30 d0 84 d2 b9 90 01 04 41 0f 45 cf 84 db ba 90 01 04 0f 44 ca 48 89 90 01 02 45 84 c0 41 0f 45 cf 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}