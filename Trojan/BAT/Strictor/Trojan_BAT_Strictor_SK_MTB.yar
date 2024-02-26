
rule Trojan_BAT_Strictor_SK_MTB{
	meta:
		description = "Trojan:BAT/Strictor.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 05 06 08 5d 13 06 06 17 58 08 5d 13 0b 07 11 0b 91 11 05 58 13 0c 07 11 06 91 13 0d 11 0d 11 07 06 1f 16 5d 91 61 13 0e 11 0e 11 0c 59 13 0f 07 11 06 11 0f 11 05 5d d2 9c 06 17 58 0a 06 08 11 08 17 58 5a fe 04 13 10 11 10 2d ae } //00 00 
	condition:
		any of ($a_*)
 
}