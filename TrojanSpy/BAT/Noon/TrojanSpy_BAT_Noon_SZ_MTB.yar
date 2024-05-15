
rule TrojanSpy_BAT_Noon_SZ_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 11 06 09 6a 5d d4 07 11 06 09 6a 5d d4 91 08 11 06 08 8e 69 6a 5d d4 91 61 28 42 00 00 0a 07 11 06 17 6a 58 09 6a 5d d4 91 28 43 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 44 00 00 0a 9c 00 11 06 17 6a 58 13 06 11 06 09 17 59 6a fe 02 16 fe 01 13 07 11 07 2d a4 } //00 00 
	condition:
		any of ($a_*)
 
}