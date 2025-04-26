
rule Trojan_BAT_Keylogger_DC_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 00 40 01 00 8d 46 00 00 01 0a 2b 09 03 06 16 07 6f 60 00 00 0a 02 06 16 06 8e 69 6f 61 00 00 0a 25 0b 2d e8 } //1
		$a_01_1 = {20 e7 03 00 00 28 02 00 00 0a 00 00 08 17 58 0c 08 1f 0f fe 04 0d 09 2d e6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}