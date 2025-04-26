
rule Trojan_BAT_Seraph_SPQX_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 06 4a 17 58 54 06 4a 07 8e 69 32 da 06 1a 58 16 52 de 30 73 3a 00 00 0a 2b bc } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}