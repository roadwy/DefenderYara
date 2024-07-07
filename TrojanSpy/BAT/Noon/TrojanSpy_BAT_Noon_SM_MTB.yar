
rule TrojanSpy_BAT_Noon_SM_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 06 11 06 9a 1f 10 28 18 01 00 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}