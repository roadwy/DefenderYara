
rule Backdoor_BAT_NanoBot_PA_MTB{
	meta:
		description = "Backdoor:BAT/NanoBot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 4f 00 4e 00 54 00 5f 00 4d 00 55 00 54 00 41 00 54 00 45 00 } //01 00  DONT_MUTATE
		$a_03_1 = {8e 69 17 da 17 d8 13 90 01 01 16 13 90 01 01 2b 90 00 } //01 00 
		$a_03_2 = {8e 69 5d 91 09 11 90 01 01 09 8e 69 5d 91 61 90 02 10 17 d6 90 02 08 8e 69 5d 91 da 20 90 02 08 d6 20 90 02 08 5d b4 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}