
rule Trojan_BAT_FormBook_MBEH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 0a 11 09 6f 90 01 01 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 72 86 0e 00 70 28 90 01 01 00 00 0a 13 0d 11 0d 2c 0d 00 12 0b 28 90 01 01 00 00 0a 13 0c 00 2b 42 11 05 11 08 9a 72 8a 0e 00 70 28 90 01 01 00 00 0a 13 0e 11 0e 2c 0d 00 12 0b 28 90 01 01 00 00 0a 13 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}