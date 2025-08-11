
rule Trojan_Win64_BlackWidow_BLL_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.BLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 6f c1 66 0f 61 ca 44 30 14 0f 66 0f 38 30 ?? 66 0f 38 1d ?? 66 0f 38 1d e0 66 0f 6c ca } //5
		$a_03_1 = {66 0f 6d da 66 0f 6c d3 48 89 c8 66 0f 6c ?? 66 0f 62 c2 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}