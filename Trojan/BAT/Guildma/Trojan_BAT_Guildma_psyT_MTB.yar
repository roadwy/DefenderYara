
rule Trojan_BAT_Guildma_psyT_MTB{
	meta:
		description = "Trojan:BAT/Guildma.psyT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {28 32 00 00 0a 03 6f 33 00 00 0a 0d 02 02 8e b7 17 da 91 1f 70 61 0a 02 8e b7 17 d6 8d 25 00 00 01 0c 16 02 8e b7 17 da 13 06 13 05 2b 2d 08 11 05 02 11 05 91 06 61 09 11 04 91 61 b4 9c 11 04 03 6f 34 00 00 0a 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 31 cd 08 74 26 00 00 01 02 8e b7 18 da 17 d6 8d 25 00 00 01 28 35 00 00 0a 74 09 00 00 1b 0c 08 2a } //00 00 
	condition:
		any of ($a_*)
 
}