
rule PWS_BAT_GameThief_PA_MTB{
	meta:
		description = "PWS:BAT/GameThief.PA!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {47 00 72 00 6f 00 77 00 74 00 6f 00 70 00 69 00 61 00 } //01 00  Growtopia
		$a_01_1 = {50 72 6f 63 65 73 73 53 74 65 61 6c 65 72 } //01 00  ProcessStealer
		$a_01_2 = {53 00 74 00 65 00 61 00 6c 00 65 00 72 00 20 00 77 00 69 00 74 00 68 00 20 00 41 00 41 00 50 00 20 00 62 00 79 00 70 00 61 00 73 00 73 00 } //01 00  Stealer with AAP bypass
		$a_01_3 = {53 00 74 00 65 00 61 00 6c 00 20 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 54 00 6f 00 6b 00 65 00 6e 00 } //01 00  Steal Google Token
		$a_01_4 = {53 00 70 00 61 00 6d 00 6d 00 65 00 72 00 } //00 00  Spammer
	condition:
		any of ($a_*)
 
}