
rule Backdoor_BAT_Mokes_AAZU_MTB{
	meta:
		description = "Backdoor:BAT/Mokes.AAZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 18 58 1d 58 1f 09 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1d 58 1f 09 59 91 61 28 90 01 01 00 00 0a 03 08 20 87 10 00 00 58 20 86 10 00 00 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}