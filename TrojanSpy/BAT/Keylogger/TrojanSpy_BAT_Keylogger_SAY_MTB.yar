
rule TrojanSpy_BAT_Keylogger_SAY_MTB{
	meta:
		description = "TrojanSpy:BAT/Keylogger.SAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1d 28 0f 00 00 0a 72 ?? ?? ?? 70 28 10 00 00 0a 28 11 00 00 0a 2d 20 28 12 00 00 0a 6f 13 00 00 0a 1d 28 0f 00 00 0a 72 ?? ?? ?? 70 28 10 00 00 0a 17 28 14 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}