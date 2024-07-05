
rule Backdoor_BAT_Crysan_NGAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.NGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 11 03 11 00 11 03 91 11 02 11 03 11 02 6f 90 01 01 00 00 0a 5d 28 90 01 01 00 00 06 61 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}