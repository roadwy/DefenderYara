
rule Trojan_BAT_FormBook_WGB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.WGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 0d 04 03 6f ?? 00 00 0a 59 13 04 11 04 19 fe 04 16 fe 01 13 05 11 05 2c 2e 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a } //5
		$a_03_1 = {25 16 12 03 28 ?? 00 00 0a 9c 25 17 12 03 28 9e 00 00 0a 9c 25 18 12 03 28 ?? 00 00 0a 9c 13 07 16 13 08 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}