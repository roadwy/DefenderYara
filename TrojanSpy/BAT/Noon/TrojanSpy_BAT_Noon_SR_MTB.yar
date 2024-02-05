
rule TrojanSpy_BAT_Noon_SR_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 11 04 11 05 6f 2a 00 00 0a 13 08 07 11 04 11 05 6f 2a 00 00 0a 13 09 11 09 28 2b 00 00 0a 13 0a 09 08 11 0a d2 9c 11 05 17 58 13 05 11 05 07 6f 2c 00 00 0a 32 c9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_BAT_Noon_SR_MTB_2{
	meta:
		description = "TrojanSpy:BAT/Noon.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 11 04 07 8e 69 5d 07 11 04 07 8e 69 5d 91 08 11 04 1f 16 5d 6f 90 01 03 0a 61 28 90 01 03 0a 07 11 04 17 58 07 8e 69 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d ac 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}