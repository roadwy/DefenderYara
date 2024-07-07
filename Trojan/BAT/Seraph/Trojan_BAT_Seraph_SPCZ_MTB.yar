
rule Trojan_BAT_Seraph_SPCZ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 07 02 11 09 06 28 90 01 03 06 6f 90 01 03 0a 11 08 17 58 13 08 11 08 11 05 8e 69 32 ad 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}