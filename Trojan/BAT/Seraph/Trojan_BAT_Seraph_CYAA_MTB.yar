
rule Trojan_BAT_Seraph_CYAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.CYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 0e 06 07 02 07 91 1f 7b 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ec } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}