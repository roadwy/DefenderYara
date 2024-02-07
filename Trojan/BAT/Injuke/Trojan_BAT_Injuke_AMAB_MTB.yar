
rule Trojan_BAT_Injuke_AMAB_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 07 11 04 11 01 11 04 91 11 00 11 04 11 00 28 90 01 01 00 00 06 5d 6f 90 01 01 00 00 0a 61 d2 9c 90 00 } //01 00 
		$a_81_1 = {48 74 74 70 43 6c 69 65 6e 74 } //00 00  HttpClient
	condition:
		any of ($a_*)
 
}