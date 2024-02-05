
rule VirTool_BAT_CryptInject_AC_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 0c 11 15 11 0b 9e 11 0d 11 15 11 09 9e 11 09 1b 64 11 09 1f 1b 62 60 13 08 11 0a 19 64 11 0a 1f 1d 62 60 13 09 11 0b 1d 64 11 0b 1f 19 62 60 13 0a 11 08 1f 0b 64 11 08 1f 15 62 60 13 0b 11 15 17 58 13 15 } //01 00 
		$a_01_1 = {12 00 28 38 00 00 06 06 6f 22 00 00 0a 16 31 10 06 16 6f 23 00 00 0a 20 ae 00 00 00 fe 01 2b 01 16 0b 28 24 00 00 0a 28 25 00 00 0a 0c 08 08 1f 3c 58 4b e0 58 25 1c 58 49 0d 25 1f 14 58 49 13 04 16 e0 13 05 16 13 06 1f 18 58 11 04 58 13 07 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}