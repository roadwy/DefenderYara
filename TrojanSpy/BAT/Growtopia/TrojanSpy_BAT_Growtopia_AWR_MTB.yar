
rule TrojanSpy_BAT_Growtopia_AWR_MTB{
	meta:
		description = "TrojanSpy:BAT/Growtopia.AWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 16 13 07 2b 1f 11 06 11 07 9a 28 ?? 00 00 0a 13 08 07 11 08 6f ?? 00 00 0a 6f ?? 00 00 0a 11 07 17 d6 13 07 11 07 11 06 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}