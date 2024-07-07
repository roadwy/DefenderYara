
rule Trojan_BAT_Seraph_FAU_MTB{
	meta:
		description = "Trojan:BAT/Seraph.FAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 2d 22 26 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 1b 2d 11 26 02 07 28 90 01 01 00 00 06 18 2d 09 26 de 0c 0a 2b dc 0b 2b ed 0c 2b f5 26 de c9 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}