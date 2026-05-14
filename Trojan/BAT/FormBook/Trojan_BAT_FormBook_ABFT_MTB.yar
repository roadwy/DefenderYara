
rule Trojan_BAT_FormBook_ABFT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0e 06 11 07 08 58 61 10 06 02 08 11 07 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 13 0b 11 0b 13 0a 11 0a } //5
		$a_03_1 = {03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 2b a8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}