
rule Trojan_BAT_FormBook_PNC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 07 17 58 20 ff 00 00 00 5f 13 07 11 05 11 04 11 07 95 58 20 ff 00 00 00 5f 13 05 11 04 11 07 95 13 06 11 04 11 07 11 04 11 05 95 9e 11 04 11 05 11 06 9e 11 04 11 07 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 13 11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c 00 11 12 17 58 13 12 11 12 09 8e 69 fe 04 13 15 11 15 2d 90 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}