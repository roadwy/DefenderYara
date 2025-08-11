
rule Trojan_BAT_FormBook_PGT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0c 02 11 0c 7b 98 00 00 04 7b 94 00 00 04 11 0c 7b 98 00 00 04 7b 94 00 00 04 60 11 0c 7b 98 00 00 04 7b 94 00 00 04 5f 11 0b 11 0b 60 11 0b 5f 6f ?? 00 00 0a 7d 96 00 00 04 11 0c 04 11 0c 7b 98 00 00 04 7b 95 00 00 04 7b 93 00 00 04 6f ?? 00 00 0a 59 7d 97 00 00 04 7e ?? 00 00 04 25 2d 17 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}