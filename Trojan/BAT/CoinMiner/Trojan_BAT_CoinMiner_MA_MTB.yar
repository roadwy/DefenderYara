
rule Trojan_BAT_CoinMiner_MA_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 90 01 03 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de 90 00 } //01 00 
		$a_01_1 = {4d 69 6e 65 73 77 65 65 70 65 72 5f 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } //01 00  Minesweeper_WindowsFormsApp
		$a_01_2 = {67 65 74 5f 44 61 72 6b 52 65 64 } //01 00  get_DarkRed
		$a_01_3 = {67 65 74 5f 49 73 48 69 64 64 65 6e } //00 00  get_IsHidden
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_CoinMiner_MA_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {70 07 1f 64 73 90 01 03 0a 0c 73 90 01 03 0a 0d 09 20 00 01 00 00 6f 90 01 03 0a 09 17 6f 90 01 03 0a 09 08 1f 10 6f 90 01 03 0a 06 6f 90 01 03 0a 13 04 73 90 01 03 0a 13 05 11 05 11 04 17 73 90 01 03 0a 13 06 11 06 02 16 02 8e 69 6f 90 01 03 0a 11 06 6f 90 01 03 0a de 90 00 } //01 00 
		$a_01_1 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00  GetFolderPath
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_4 = {73 65 74 5f 4b 65 79 53 69 7a 65 } //01 00  set_KeySize
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_6 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_7 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_8 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //00 00  RijndaelManaged
	condition:
		any of ($a_*)
 
}