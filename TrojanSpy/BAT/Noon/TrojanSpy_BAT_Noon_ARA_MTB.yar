
rule TrojanSpy_BAT_Noon_ARA_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 11 10 07 11 10 91 17 8d ?? ?? ?? 01 25 16 20 c6 00 00 00 9c 11 10 17 5d 91 61 d2 9c 00 11 10 17 58 13 10 11 10 07 8e 69 fe 04 13 11 11 11 2d ce } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}