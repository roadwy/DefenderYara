
rule Trojan_BAT_Quasar_AQI_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 12 2b 23 11 11 11 12 9a 13 13 00 11 13 28 ?? ?? ?? 0a 13 14 11 14 2c 07 00 07 17 58 0b 2b 0f 00 11 12 17 58 13 12 11 12 11 11 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}