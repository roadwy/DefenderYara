
rule Trojan_BAT_Quasar_AQU_MTB{
	meta:
		description = "Trojan:BAT/Quasar.AQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 00 06 03 6f 90 01 03 0a 0b 07 8e 16 fe 03 0c 08 2c 05 00 07 0d de 0f 14 0d de 0b 06 2c 07 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}