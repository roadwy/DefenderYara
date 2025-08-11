
rule TrojanSpy_BAT_Reline_SK_MTB{
	meta:
		description = "TrojanSpy:BAT/Reline.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 3a 06 00 00 00 28 13 00 00 06 0a 06 39 0a 00 00 00 06 16 06 8e 69 28 04 00 00 0a dd 13 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}