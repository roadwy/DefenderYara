
rule Trojan_BAT_KeyLogger_MMO_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.MMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 05 75 0a 00 00 01 02 08 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 11 05 74 90 01 01 00 00 01 6f 90 01 01 00 00 0a 11 0a 90 00 } //01 00 
		$a_01_1 = {4b 65 79 4c 6f 67 67 65 72 2e 65 78 65 } //00 00  KeyLogger.exe
	condition:
		any of ($a_*)
 
}