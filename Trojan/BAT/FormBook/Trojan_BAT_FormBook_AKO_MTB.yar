
rule Trojan_BAT_FormBook_AKO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 15 12 15 28 ?? 00 00 0a 16 61 d2 13 16 12 15 28 ?? 00 00 0a 16 61 d2 13 17 12 15 28 ?? 00 00 0a 16 61 d2 13 18 19 8d ?? 00 00 01 25 16 11 16 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AKO_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 fe 01 13 0b 11 0b 2c 5a 00 03 19 8d ?? 00 00 01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 28 ?? 00 00 0a 13 0d 12 0d 28 ?? 00 00 0a 18 5d 17 fe 01 13 0c 11 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_AKO_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 08 09 6f ?? 01 00 0a 13 04 04 03 6f ?? 01 00 0a 59 13 05 11 05 19 32 29 03 12 04 28 ?? 01 00 0a 6f ?? 01 00 0a 03 12 04 28 ?? 01 00 0a 6f ?? 01 00 0a 03 12 04 28 ?? 01 00 0a 6f ?? 01 00 0a 2b 47 11 05 16 31 42 19 8d ?? 00 00 01 25 16 12 04 28 ?? 01 00 0a 9c 25 17 12 04 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}