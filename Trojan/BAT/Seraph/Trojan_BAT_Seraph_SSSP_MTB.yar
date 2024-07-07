
rule Trojan_BAT_Seraph_SSSP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SSSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1e 11 0d 6f 90 01 03 0a 13 25 11 0c 11 25 11 15 59 61 13 0c 11 15 11 0c 19 58 1e 63 59 13 15 11 0d 6f 90 01 03 06 2d d9 de 0c 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}