
rule Trojan_BAT_Seraph_AQAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 50 08 91 0d 02 50 08 02 50 06 08 59 17 59 91 9c 02 50 06 08 59 17 59 09 9c 08 17 58 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}