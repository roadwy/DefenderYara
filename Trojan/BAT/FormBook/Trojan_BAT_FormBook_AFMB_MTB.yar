
rule Trojan_BAT_FormBook_AFMB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 07 17 da 0d 20 1a ba 15 00 13 04 2b 16 08 03 74 ?? 00 00 1b 11 04 91 6f ?? 01 00 0a 00 11 04 17 d6 13 04 11 04 09 31 e5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}