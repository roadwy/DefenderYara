
rule TrojanSpy_BAT_Keylogger_AK_MTB{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 05 00 11 05 13 06 16 13 07 2b 4f 11 06 11 07 9a 13 08 00 11 08 06 07 28 31 00 00 0a 28 34 00 00 0a 13 09 11 09 2c 2c 00 73 36 00 00 0a 13 0a 02 7b 05 00 00 04 11 08 02 7b 06 00 00 04 72 c3 00 00 70 11 0a 28 0c 00 00 06 00 11 08 28 37 00 00 0a 00 00 00 11 07 17 58 13 07 11 07 11 06 8e 69 32 a9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}