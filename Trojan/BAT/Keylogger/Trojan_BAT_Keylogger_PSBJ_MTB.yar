
rule Trojan_BAT_Keylogger_PSBJ_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.PSBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 7e 08 00 00 04 28 19 00 00 0a 16 fe 01 0a 06 2c 0d 00 7e 08 00 00 04 28 1a 00 00 0a 26 00 7e 09 00 00 04 28 1b 00 00 0a 16 fe 01 0b 07 2c 1c 00 7e 09 00 00 04 28 1c 00 00 0a 0c } //5
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_2 = {57 72 69 74 65 4c 69 6e 65 } //1 WriteLine
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}