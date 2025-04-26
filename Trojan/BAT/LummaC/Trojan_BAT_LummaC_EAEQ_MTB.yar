
rule Trojan_BAT_LummaC_EAEQ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.EAEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 02 00 00 06 0c 72 61 00 00 70 28 01 00 00 0a 0d 72 93 00 00 70 28 01 00 00 0a 13 04 73 02 00 00 0a 13 05 73 03 00 00 0a 13 06 11 06 11 05 09 11 04 6f 04 00 00 0a 17 73 05 00 00 0a 13 07 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}