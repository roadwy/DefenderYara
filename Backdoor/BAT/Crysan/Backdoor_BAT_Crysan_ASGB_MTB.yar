
rule Backdoor_BAT_Crysan_ASGB_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ASGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 16 91 1f 1f 61 6a 1e 62 09 1d 91 1f 21 61 6a 1f 20 62 09 19 91 20 ed 00 00 00 61 6a 16 62 09 17 91 1f 11 61 6a 1f 10 62 09 1c 91 20 f1 00 00 00 61 6a 1f 28 62 09 1a 91 20 d2 00 00 00 61 6a 1f 18 62 09 1b 91 20 f9 00 00 00 61 6a 1f 30 62 09 18 91 20 e4 00 00 00 61 6a } //01 00 
		$a_03_1 = {16 fe 01 0a 06 2c 05 28 90 01 01 00 00 06 20 dc 05 00 00 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}