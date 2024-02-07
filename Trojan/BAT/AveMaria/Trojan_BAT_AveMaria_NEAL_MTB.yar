
rule Trojan_BAT_AveMaria_NEAL_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 09 07 09 07 8e 69 5d 91 02 09 91 61 d2 9c 09 17 58 0d 09 02 8e 69 32 e7 } //01 00 
		$a_01_1 = {55 6a 69 6b 73 6c 79 74 6f 67 67 6d 66 } //00 00  Ujikslytoggmf
	condition:
		any of ($a_*)
 
}