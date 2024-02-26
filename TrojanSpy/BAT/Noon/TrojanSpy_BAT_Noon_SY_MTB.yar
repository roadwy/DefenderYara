
rule TrojanSpy_BAT_Noon_SY_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 07 20 00 dc 00 00 5d 13 08 08 11 08 91 13 09 11 07 1f 16 5d 13 0a 08 11 08 11 09 1f 16 8d c5 00 00 01 25 d0 5d 00 00 04 28 e1 00 00 0a 11 0a 91 61 08 11 07 17 58 20 00 dc 00 00 5d 91 09 58 09 5d 59 d2 9c 00 11 07 17 58 13 07 11 07 20 00 dc 00 00 fe 04 13 0b 11 0b 2d a4 } //00 00 
	condition:
		any of ($a_*)
 
}