
rule Trojan_BAT_FormBook_MBEP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 04 06 11 08 5d 13 0b 06 17 58 08 5d 13 0c 07 11 04 91 13 0d 20 00 01 00 00 13 05 11 0d 09 11 0b 91 61 07 11 0c 91 59 11 05 58 11 05 5d 13 0e 07 11 04 11 0e d2 9c 06 17 58 0a 06 08 11 07 17 58 5a fe 04 13 0f 11 0f 2d b3 } //01 00 
		$a_01_1 = {57 65 61 74 68 65 72 46 6f 72 65 63 61 73 74 5f 43 6c 69 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 } //00 00  WeatherForecast_Client.Propertie
	condition:
		any of ($a_*)
 
}