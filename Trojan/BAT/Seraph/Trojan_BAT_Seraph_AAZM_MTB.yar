
rule Trojan_BAT_Seraph_AAZM_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 08 02 50 06 08 59 17 59 91 9c 02 50 06 08 59 17 59 09 9c 16 2d 14 16 2d da 08 17 58 0c 16 2d d5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}