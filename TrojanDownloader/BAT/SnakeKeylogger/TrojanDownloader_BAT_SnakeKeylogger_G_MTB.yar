
rule TrojanDownloader_BAT_SnakeKeylogger_G_MTB{
	meta:
		description = "TrojanDownloader:BAT/SnakeKeylogger.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0c 00 00 0f 00 "
		
	strings :
		$a_03_0 = {0a 0a 00 06 02 73 90 01 03 0a 6f 90 01 03 0a 0b de 90 01 01 90 0a 48 00 20 90 01 03 00 2b 90 01 02 2b 90 01 01 28 90 01 03 0a 2b 90 01 02 de 90 01 01 26 90 01 02 de 00 73 90 00 } //01 00 
		$a_01_1 = {41 64 64 53 65 63 6f 6e 64 73 } //01 00  AddSeconds
		$a_01_2 = {44 61 74 65 54 69 6d 65 } //01 00  DateTime
		$a_01_3 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //01 00  SecurityProtocol
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_6 = {6f 70 5f 47 72 65 61 74 65 72 54 68 61 6e } //01 00  op_GreaterThan
		$a_01_7 = {6f 70 5f 4c 65 73 73 54 68 61 6e } //01 00  op_LessThan
		$a_01_8 = {67 65 74 5f 4e 6f 77 } //01 00  get_Now
		$a_01_9 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_10 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_11 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}