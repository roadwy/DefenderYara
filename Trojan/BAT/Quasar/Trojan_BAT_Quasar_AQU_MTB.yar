
rule Trojan_BAT_Quasar_AQU_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 03 6f ?? ?? ?? 0a 0b 07 8e 16 fe 03 0c 08 2c 05 00 07 0d de 0f 14 0d de 0b 06 2c 07 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Quasar_AQU_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.AQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0f 11 0f 2c 25 00 72 ?? 05 00 70 11 0e 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 00 17 13 0b ?? ?? ?? ?? ?? 00 de 05 26 00 00 de 00 00 11 0d 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}