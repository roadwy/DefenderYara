
rule Trojan_BAT_FormBook_VTB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.VTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 06 11 04 6f ?? 01 00 0a 13 14 09 07 6f ?? 00 00 0a 59 13 06 11 06 19 fe 04 16 fe 01 13 0c 11 0c 2c 54 19 8d 0b 00 00 01 25 16 12 14 28 ?? 01 00 0a 9c 25 17 12 14 28 ?? 01 00 0a 9c 25 18 12 14 28 ?? 01 00 0a 9c 13 0d 11 09 20 7e a3 55 48 28 ?? 00 00 06 28 ?? 01 00 0a 2c 03 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}