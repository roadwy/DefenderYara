
rule TrojanSpy_BAT_Noon_SC_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 07 91 13 09 11 06 17 58 08 5d 13 0a 07 11 06 91 11 09 61 07 11 0a 91 59 20 00 01 00 00 58 13 0b 07 11 06 11 0b 20 ff 00 00 00 5f d2 9c 11 06 17 58 13 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanSpy_BAT_Noon_SC_MTB_2{
	meta:
		description = "TrojanSpy:BAT/Noon.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 07 91 07 11 04 17 58 09 5d 91 13 08 08 11 04 1f 16 5d 91 13 09 11 09 61 11 08 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 0a 07 11 04 11 0a d2 9c 11 04 17 58 13 04 11 07 17 58 13 07 11 07 11 06 8e 69 32 b9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}