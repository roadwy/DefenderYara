
rule Backdoor_BAT_Crysan_CG_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0c 16 13 04 2b 18 08 11 04 07 11 04 07 8e 69 5d 91 06 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 fe 04 2d } //00 00 
	condition:
		any of ($a_*)
 
}