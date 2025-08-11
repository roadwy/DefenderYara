
rule Trojan_Win64_Latrodectus_MZD_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.MZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6c c2 66 0f 6c d1 66 0f 6f c8 45 8a 14 11 66 0f 6c ca 66 0f f9 d0 66 0f 6f cb 66 0f 6f d8 66 0f 6c d3 } //5
		$a_01_1 = {66 0f f9 d0 66 0f f9 cb 44 30 14 0f 66 0f 6a ca 66 0f 6d da 66 0f 38 30 d0 66 0f 61 ca 66 0f 6f c1 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}