
rule Trojan_BAT_FormBook_AADE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 17 58 20 ff 00 00 00 5f 0d 11 04 11 06 09 95 58 20 ff 00 00 00 5f 13 04 11 06 09 95 13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 11 07 11 08 d4 07 11 08 d4 91 11 06 11 06 09 95 11 06 11 04 95 58 20 ff 00 00 00 5f 95 61 d2 9c 11 08 17 6a 58 13 08 11 08 11 07 8e 69 17 59 6a 31 9f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}