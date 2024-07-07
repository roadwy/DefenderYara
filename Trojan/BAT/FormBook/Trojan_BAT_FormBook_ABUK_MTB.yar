
rule Trojan_BAT_FormBook_ABUK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 da 13 07 16 13 08 2b 23 08 09 07 11 08 18 6f 90 01 01 01 00 0a 1f 10 28 90 01 02 00 0a b4 6f 90 01 02 00 0a 00 09 17 d6 0d 11 08 18 d6 13 08 11 08 11 07 31 d7 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}