
rule Trojan_BAT_Remcos_FA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 2b 02 7b 90 01 03 04 25 6f 90 01 03 0a 12 00 28 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 06 17 58 0a 20 e8 03 00 00 28 90 01 03 0a 06 1f 0a 32 d0 90 00 } //01 00 
		$a_81_1 = {53 61 6e 64 62 6f 78 69 65 20 53 74 61 72 74 } //01 00  Sandboxie Start
		$a_81_2 = {43 6f 6e 73 6f 6c 65 41 70 70 } //01 00  ConsoleApp
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //00 00  Form1_Load
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Remcos_FA_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_02_0 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 90 02 05 2e 50 72 6f 70 65 72 74 69 65 73 90 00 } //01 00 
		$a_02_1 = {43 6f 6e 73 6f 6c 65 41 70 70 90 02 05 2e 65 78 65 90 00 } //01 00 
		$a_02_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 39 00 31 00 2e 00 32 00 34 00 33 00 2e 00 34 00 34 00 2e 00 32 00 32 00 2f 00 90 02 0f 2e 00 70 00 6e 00 67 00 90 00 } //01 00 
		$a_81_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_5 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_81_6 = {47 65 74 54 79 70 65 73 } //00 00  GetTypes
	condition:
		any of ($a_*)
 
}