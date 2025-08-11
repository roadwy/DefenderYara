
rule Trojan_BAT_FormBook_LAT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.LAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 11 04 11 05 6f ?? 00 00 0a 13 06 04 03 6f ?? 00 00 0a 59 13 07 11 07 19 fe 04 16 fe 01 13 08 11 08 2c 2e 00 03 12 06 28 ?? 00 00 0a 6f 89 00 00 0a 00 03 12 06 28 8a 00 00 0a 6f ?? 00 00 0a 00 03 12 06 28 8b 00 00 0a 6f 89 00 00 0a 00 00 2b 58 11 07 16 fe 02 13 09 11 09 2c 4d 00 19 8d 4f 00 00 01 25 16 12 06 28 ?? 00 00 0a 9c 25 17 12 06 28 8a 00 00 0a 9c 25 18 12 06 28 8b 00 00 0a 9c 13 0a 16 13 0b 2b 14 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}