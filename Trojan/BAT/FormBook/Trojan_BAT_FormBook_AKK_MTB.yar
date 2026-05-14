
rule Trojan_BAT_FormBook_AKK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 fe 01 13 15 11 15 2c 05 38 ff 00 00 00 02 11 05 11 06 6f ?? 00 00 0a 13 0a 03 07 6f ?? 00 00 0a 59 13 0b 07 12 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 59 25 13 0b 16 fe 02 16 fe 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AKK_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 00 11 04 02 6f ?? 00 00 0a fe 04 16 fe 01 13 0f 11 0f 2c 05 38 ?? 01 00 00 11 05 02 6f ?? 00 00 0a fe 04 16 fe 01 13 10 11 10 2c 05 } //2
		$a_03_1 = {11 04 11 05 6f ?? 00 00 0a 13 07 12 07 28 ?? 00 00 0a 13 08 12 07 28 ?? 00 00 0a 13 09 12 07 28 ?? 00 00 0a 13 0a 03 13 12 11 12 2c 1d 00 11 08 28 ?? 00 00 06 13 08 11 09 28 ?? 00 00 06 13 09 11 0a 28 ?? 00 00 06 13 0a 00 11 08 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}