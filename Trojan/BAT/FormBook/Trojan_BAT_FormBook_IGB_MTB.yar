
rule Trojan_BAT_FormBook_IGB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.IGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 0d 04 03 6f ?? 00 00 0a 59 13 04 11 04 19 fe 04 16 fe 01 13 05 11 05 2c 2e 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 58 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}