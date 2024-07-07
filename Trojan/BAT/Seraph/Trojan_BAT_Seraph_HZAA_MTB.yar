
rule Trojan_BAT_Seraph_HZAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.HZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 07 07 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 2b 0c 00 28 90 01 01 00 00 06 0a de 03 26 de 00 06 2c f1 73 90 01 01 00 00 0a 0d 06 73 90 01 01 00 00 0a 13 04 11 04 08 16 73 90 01 01 00 00 0a 13 05 11 05 09 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 0a de 2c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}