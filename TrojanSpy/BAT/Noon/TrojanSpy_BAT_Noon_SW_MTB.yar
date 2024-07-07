
rule TrojanSpy_BAT_Noon_SW_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 5d 13 04 06 1f 16 5d 13 0a 06 17 58 09 5d 13 0b 07 11 04 91 11 06 11 0a 91 61 13 0c 20 00 01 00 00 13 05 11 0c 07 11 0b 91 59 11 05 58 11 05 5d 13 0d 07 11 04 11 0d d2 9c 06 17 58 0a 06 09 11 07 17 58 5a fe 04 13 0e 11 0e 2d b2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}