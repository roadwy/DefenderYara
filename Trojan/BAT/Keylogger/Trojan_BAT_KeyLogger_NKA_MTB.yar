
rule Trojan_BAT_KeyLogger_NKA_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.NKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 22 00 00 0a 6f 90 01 01 00 00 0a 00 00 28 90 01 01 00 00 06 0b 07 16 28 90 01 01 00 00 06 26 06 6f 90 01 01 00 00 06 16 fe 01 0d 09 2c 10 00 06 6f 90 01 01 00 00 06 00 06 6f 90 01 01 00 00 06 90 00 } //5
		$a_01_1 = {4b 00 65 00 79 00 73 00 74 00 72 00 6f 00 6b 00 65 00 73 00 20 00 73 00 61 00 76 00 65 00 64 00 20 00 66 00 72 00 6f 00 6d 00 20 00 75 00 73 00 65 00 72 00 } //1 Keystrokes saved from user
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}