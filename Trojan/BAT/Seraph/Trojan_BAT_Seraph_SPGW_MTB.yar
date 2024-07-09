
rule Trojan_BAT_Seraph_SPGW_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPGW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 07 11 04 16 73 ?? ?? ?? 0a 0c 08 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 13 05 de 6c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}