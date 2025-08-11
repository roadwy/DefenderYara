
rule Trojan_BAT_DarkCloud_ADC_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 1f 63 58 0c 00 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 17 59 25 13 04 16 fe 02 16 fe 01 13 0b 11 0b 2c 02 2b 46 03 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 17 59 25 13 04 16 fe 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}