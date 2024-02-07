
rule Trojan_BAT_AsyncRat_ABDY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ABDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 05 09 11 05 08 02 11 05 18 5a 18 6f 90 01 03 0a 6f 90 01 03 0a 9c 06 6f 90 01 03 0a 2d db de 0d 06 2c 06 06 6f 90 01 03 0a 17 2c f4 dc 90 00 } //01 00 
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_2 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_3 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //00 00  CreateDelegate
	condition:
		any of ($a_*)
 
}