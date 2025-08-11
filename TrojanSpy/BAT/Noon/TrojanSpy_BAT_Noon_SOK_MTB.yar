
rule TrojanSpy_BAT_Noon_SOK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 09 11 0b 18 5d 16 fe 01 11 0b 19 5d 16 fe 01 60 2d 03 17 2b 01 16 6a d6 13 09 11 0b 17 d6 13 0b 11 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}