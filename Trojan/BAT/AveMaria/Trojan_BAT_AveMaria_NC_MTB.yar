
rule Trojan_BAT_AveMaria_NC_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 74 3f 00 70 d0 90 01 02 00 02 28 90 01 02 00 0a 6f 90 01 02 00 0a 73 90 01 02 00 0a 0b 90 00 } //01 00 
		$a_01_1 = {49 6f 6c 68 65 } //00 00  Iolhe
	condition:
		any of ($a_*)
 
}