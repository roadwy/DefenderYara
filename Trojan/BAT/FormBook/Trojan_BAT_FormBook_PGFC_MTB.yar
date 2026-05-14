
rule Trojan_BAT_FormBook_PGFC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PGFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 20 b3 00 00 00 0d 16 13 04 2b 19 11 04 1b 5d 16 fe 01 2c 0a 08 11 04 08 11 04 91 09 61 9c 11 04 17 d6 13 04 11 04 08 8e 69 fe 04 2d de 08 0a 06 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}