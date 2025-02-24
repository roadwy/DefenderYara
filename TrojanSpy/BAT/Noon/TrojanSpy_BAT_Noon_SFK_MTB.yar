
rule TrojanSpy_BAT_Noon_SFK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 0a 07 11 0a 91 11 04 11 0b 95 61 d2 9c 00 11 0a 17 58 13 0a 11 0a 07 8e 69 fe 04 13 0e 11 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}