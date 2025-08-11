
rule TrojanSpy_BAT_Growtopia_ARG_MTB{
	meta:
		description = "TrojanSpy:BAT/Growtopia.ARG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 28 00 07 09 06 09 91 72 ?? 00 00 70 09 72 ?? 00 00 70 28 ?? 00 00 0a 5d 28 ?? 00 00 0a 61 d2 9c 00 09 13 04 11 04 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}