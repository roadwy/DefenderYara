
rule Trojan_BAT_Injector_JAKS_MTB{
	meta:
		description = "Trojan:BAT/Injector.JAKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0b 06 2c 45 06 8e 2c 41 06 73 1c 00 00 0a 0c 08 16 73 1d 00 00 0a 0d 09 73 1e 00 00 0a 13 04 11 04 6f 90 01 03 0a 0b de 20 11 04 2c 07 11 04 6f 90 01 03 0a dc 09 2c 06 09 6f 90 01 03 0a dc 08 2c 06 08 6f 90 01 03 0a dc 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}