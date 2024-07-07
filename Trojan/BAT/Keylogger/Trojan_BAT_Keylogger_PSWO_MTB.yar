
rule Trojan_BAT_Keylogger_PSWO_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.PSWO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2c 3a 00 04 28 90 01 01 00 00 0a 0b 07 0d 12 03 fe 16 06 00 00 01 6f 90 01 01 00 00 0a 0c 08 28 90 01 01 00 00 0a 16 fe 01 13 04 11 04 2c 12 00 7e 05 00 00 04 08 28 90 01 01 00 00 0a 80 05 00 00 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}