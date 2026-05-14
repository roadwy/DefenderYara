
rule Trojan_BAT_FormBook_AQOB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AQOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 13 08 09 06 6f ?? 00 00 0a 59 13 09 06 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 10 11 10 2c 05 38 ?? 00 00 00 06 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 11 11 11 2c 02 2b 6c 06 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 08 5a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}