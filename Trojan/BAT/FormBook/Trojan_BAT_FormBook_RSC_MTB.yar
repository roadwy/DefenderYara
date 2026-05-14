
rule Trojan_BAT_FormBook_RSC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 11 05 6f ?? 00 00 0a 13 07 12 07 28 ?? 00 00 0a 13 08 12 07 28 ?? 00 00 0a 13 09 12 07 28 ?? 00 00 0a 13 0a 03 13 12 11 12 2c 1d 00 11 08 28 ?? 00 00 06 13 08 11 09 28 ?? 00 00 06 13 09 11 0a 28 ?? 00 00 06 13 0a 00 11 08 28 ?? 00 00 06 13 08 11 09 28 ?? 00 00 06 13 09 11 0a 28 ?? 00 00 06 13 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}