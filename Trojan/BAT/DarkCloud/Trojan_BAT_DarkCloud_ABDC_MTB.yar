
rule Trojan_BAT_DarkCloud_ABDC_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.ABDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 0b 18 13 04 38 ?? ff ff ff 02 8c ?? 00 00 1b 03 04 6f ?? 00 00 0a 0b 11 05 20 ?? 00 00 00 91 13 04 38 ?? ff ff ff 06 17 58 0a 05 25 5a 05 58 18 5d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_DarkCloud_ABDC_MTB_2{
	meta:
		description = "Trojan:BAT/DarkCloud.ABDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 11 06 11 08 6f ?? 01 00 0a 13 09 12 09 28 ?? 01 00 0a 20 ?? 00 00 00 fe 02 13 0a 11 0a 2c 29 07 12 09 28 ?? 01 00 0a 6e d6 0b 08 12 09 28 ?? 01 00 0a 6e d6 0c 09 12 09 28 ?? 01 00 0a 6e d6 0d 11 04 17 6a d6 13 04 00 00 11 08 1f 0a d6 13 08 11 08 11 07 31 a9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}