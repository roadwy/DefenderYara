
rule Trojan_BAT_SnakeKeylogger_ML_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0d 09 07 16 07 8e 69 6f 90 01 03 0a 13 04 28 90 01 03 0a 11 04 6f 90 01 03 0a 13 05 dd 0d 00 00 00 26 7e 90 01 01 00 00 0a 13 05 dd 90 00 } //02 00 
		$a_01_1 = {54 00 54 00 52 00 44 00 5a 00 42 00 57 00 49 00 69 00 6d 00 6a 00 4a 00 5a 00 72 00 47 00 } //02 00  TTRDZBWIimjJZrG
		$a_01_2 = {47 00 6f 00 74 00 69 00 63 00 32 00 2e 00 47 00 6f 00 74 00 69 00 63 00 32 00 } //02 00  Gotic2.Gotic2
		$a_01_3 = {4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5f 00 4a 00 69 00 74 00 5f 00 42 00 6f 00 6f 00 6c 00 54 00 6f 00 49 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //00 00  Manager_Jit_BoolToInt.exe
	condition:
		any of ($a_*)
 
}