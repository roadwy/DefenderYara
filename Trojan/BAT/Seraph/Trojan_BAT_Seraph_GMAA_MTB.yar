
rule Trojan_BAT_Seraph_GMAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 17 58 0a 06 20 00 01 00 00 5d 0a 08 11 06 06 94 58 0c 08 20 00 01 00 00 5d 0c 11 06 06 94 13 04 11 06 06 11 06 08 94 9e 11 06 08 11 04 9e 11 06 11 06 06 94 11 06 08 94 58 20 00 01 00 00 5d 94 0d 11 07 07 03 07 91 09 61 d2 9c 07 17 58 0b 07 03 8e 69 3f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}