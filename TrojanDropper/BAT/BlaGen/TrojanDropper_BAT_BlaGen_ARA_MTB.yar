
rule TrojanDropper_BAT_BlaGen_ARA_MTB{
	meta:
		description = "TrojanDropper:BAT/BlaGen.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 55 02 07 6f 90 01 04 0c 08 1f 61 32 1b 08 1f 7a 30 16 08 1f 0d 58 0d 09 1f 7a 31 05 09 1f 1a 59 0d 06 07 09 d1 9d 2b 29 08 1f 41 32 20 08 1f 5a 30 1b 08 1f 0d 58 13 04 11 04 1f 5a 31 07 11 04 1f 1a 59 13 04 06 07 11 04 d1 9d 2b 04 06 07 08 9d 07 17 58 0b 07 02 6f 90 01 04 32 a2 90 00 } //02 00 
		$a_81_1 = {74 65 6d 70 5c 41 73 73 65 6d 62 6c 79 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}