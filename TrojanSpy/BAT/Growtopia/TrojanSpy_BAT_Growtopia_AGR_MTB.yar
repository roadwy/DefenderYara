
rule TrojanSpy_BAT_Growtopia_AGR_MTB{
	meta:
		description = "TrojanSpy:BAT/Growtopia.AGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 16 1f 30 11 14 16 91 59 d2 13 17 00 11 14 13 20 16 13 21 2b 1b 11 20 11 21 91 13 22 11 15 11 17 11 22 58 d2 6f ?? 00 00 0a 00 11 21 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}