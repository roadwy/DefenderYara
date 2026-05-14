
rule Trojan_BAT_ClipBoardLogger_SX_MTB{
	meta:
		description = "Trojan:BAT/ClipBoardLogger.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 28 ?? 00 00 0a 2c 4f 07 0a 7e 03 00 00 04 72 ?? ?? 00 70 1b 8d 09 00 00 01 0c 08 16 72 ?? ?? 00 70 a2 08 17 28 ?? 00 00 0a 0d 12 03 72 ?? ?? 00 70 28 08 00 00 0a a2 08 18 72 ?? ?? 00 70 a2 08 19 06 a2 08 1a } //20
		$a_01_1 = {43 6c 69 70 62 6f 61 72 64 4c 6f 67 67 65 72 } //10 ClipboardLogger
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}