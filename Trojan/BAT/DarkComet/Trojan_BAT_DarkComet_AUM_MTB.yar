
rule Trojan_BAT_DarkComet_AUM_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 07 11 05 11 07 11 04 11 05 6f 90 01 03 0a 11 05 da 6f 90 01 03 0a 13 09 06 1f 28 90 00 } //01 00 
		$a_01_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //00 00  GetCurrentProcess
	condition:
		any of ($a_*)
 
}