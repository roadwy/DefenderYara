
rule TrojanSpy_BAT_Noon_SC_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 06 11 07 91 07 11 04 17 58 09 5d 91 13 08 08 11 04 1f 16 5d 91 13 09 11 09 61 11 08 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0a 07 11 04 11 0a d2 9c 11 04 17 58 13 04 11 07 17 58 13 07 11 07 11 06 8e 69 32 b9 } //00 00 
	condition:
		any of ($a_*)
 
}