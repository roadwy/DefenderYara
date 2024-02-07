
rule Trojan_BAT_Downloader_CAD_MTB{
	meta:
		description = "Trojan:BAT/Downloader.CAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 38 36 30 33 41 37 33 46 2d 33 38 44 38 2d 34 32 34 44 2d 41 46 31 43 2d 41 42 43 31 35 34 43 30 39 36 39 38 } //01 00  $8603A73F-38D8-424D-AF1C-ABC154C09698
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_2 = {73 69 68 6f 73 74 2e 65 78 65 } //01 00  sihost.exe
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_4 = {44 65 63 72 79 70 74 53 69 6d 70 6c 65 53 74 72 69 6e 67 } //01 00  DecryptSimpleString
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_6 = {62 75 62 69 48 6b 48 6a 35 79 } //01 00  bubiHkHj5y
		$a_01_7 = {71 55 68 35 50 72 75 7a 74 69 56 4c 36 } //01 00  qUh5PruztiVL6
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_9 = {47 65 74 54 65 6d 70 50 61 74 68 } //00 00  GetTempPath
	condition:
		any of ($a_*)
 
}