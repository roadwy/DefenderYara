
rule Backdoor_BAT_Crysan_AAXG_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AAXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {04 20 0c 00 00 00 97 29 90 01 01 00 00 11 72 ad 00 00 70 7e 90 01 01 00 00 04 20 0d 00 00 00 97 29 90 01 01 00 00 11 6f 90 01 01 00 00 0a 0a 06 28 90 01 01 00 00 06 0b 07 14 fe 03 0c 08 2c 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}