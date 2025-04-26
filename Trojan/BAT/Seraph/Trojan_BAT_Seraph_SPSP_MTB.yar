
rule Trojan_BAT_Seraph_SPSP_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 09 06 09 8e 69 5d 91 08 06 91 61 d2 9c 18 2c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}