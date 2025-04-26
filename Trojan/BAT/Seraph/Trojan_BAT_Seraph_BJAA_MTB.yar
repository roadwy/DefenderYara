
rule Trojan_BAT_Seraph_BJAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.BJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 06 07 08 59 17 59 91 9c 06 07 08 59 17 59 09 9c 08 17 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}