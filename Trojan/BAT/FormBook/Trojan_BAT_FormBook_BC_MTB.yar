
rule Trojan_BAT_FormBook_BC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 32 2c 03 19 8d ?? 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 2b 33 09 16 31 2f 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 31 0d 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 09 18 31 0d 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 03 6f ?? 00 00 0a 04 32 01 2a 07 17 58 0b 07 02 6f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}