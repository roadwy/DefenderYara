
rule Trojan_BAT_NanoBot_DB_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 2b 1a 7b 04 00 00 04 2b 16 7b 03 00 00 04 8c 24 00 00 01 2b 0d 2b 12 2b 00 2b 11 2a } //01 00 
		$a_03_1 = {1b fe 04 1c 2d 1c 26 2b 1c 2d dd 2a 0a 2b d4 06 2b dc 28 90 01 03 0a 2b d7 06 2b da 0a 2b de 06 2b de 0b 2b e2 07 2b e1 90 00 } //01 00 
		$a_81_2 = {7b 30 7d 20 77 69 74 68 20 73 70 65 65 64 7b 31 7d 20 6b 6d 2f 68 } //00 00  {0} with speed{1} km/h
	condition:
		any of ($a_*)
 
}