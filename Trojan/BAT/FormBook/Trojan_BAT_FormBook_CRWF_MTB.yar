
rule Trojan_BAT_FormBook_CRWF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CRWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 08 00 00 01 25 d0 15 00 00 04 28 90 01 03 0a 6f 90 01 03 0a 0c 73 7d 00 00 0a 0d 09 20 00 01 00 00 6f 90 01 03 0a 09 08 6f 90 01 03 0a 09 18 6f 90 01 03 0a 09 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 13 04 11 04 28 90 01 03 06 74 35 00 00 01 6f 90 01 03 0a 17 9a 80 2b 00 00 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}