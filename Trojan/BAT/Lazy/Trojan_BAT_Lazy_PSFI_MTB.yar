
rule Trojan_BAT_Lazy_PSFI_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 1f 28 28 1e 00 00 0a 72 90 01 03 70 28 90 01 03 0a 0a 06 28 90 01 03 0a 0b 07 39 90 01 03 00 00 06 72 90 01 03 70 16 28 90 01 03 0a 0c 00 08 0d 16 13 04 38 90 01 03 00 09 11 04 9a 13 05 00 11 05 72 90 01 03 70 16 28 90 01 03 0a 13 06 11 06 7e 90 01 03 04 25 2d 17 26 7e 90 01 03 04 fe 90 01 03 00 06 73 90 01 03 0a 25 80 90 01 03 04 28 01 00 00 2b 90 00 } //01 00 
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_2 = {57 72 69 74 65 4c 69 6e 65 } //01 00  WriteLine
		$a_01_3 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //01 00  GetEnumerator
		$a_01_4 = {43 61 74 68 61 79 46 75 74 75 72 65 73 46 58 43 6f 6e 66 69 67 } //01 00  CathayFuturesFXConfig
		$a_01_5 = {43 68 61 6e 67 65 48 6f 73 74 73 } //00 00  ChangeHosts
	condition:
		any of ($a_*)
 
}