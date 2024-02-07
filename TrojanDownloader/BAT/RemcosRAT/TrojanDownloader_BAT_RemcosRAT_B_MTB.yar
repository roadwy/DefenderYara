
rule TrojanDownloader_BAT_RemcosRAT_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/RemcosRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0c 00 00 0f 00 "
		
	strings :
		$a_03_0 = {08 25 17 59 0c 16 fe 90 01 01 0d 09 2c 90 01 01 2b 90 01 01 2b 90 01 01 6f 90 01 03 0a 2b 90 01 01 17 2b 90 01 01 16 2b 90 01 01 2d 90 01 01 07 6f 90 01 03 0a 90 0a 2b 00 07 06 08 91 2b 90 00 } //01 00 
		$a_01_1 = {41 64 64 53 65 63 6f 6e 64 73 } //01 00  AddSeconds
		$a_01_2 = {44 61 74 65 54 69 6d 65 } //01 00  DateTime
		$a_01_3 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //01 00  SecurityProtocol
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_5 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_6 = {6f 70 5f 47 72 65 61 74 65 72 54 68 61 6e } //01 00  op_GreaterThan
		$a_01_7 = {6f 70 5f 4c 65 73 73 54 68 61 6e } //01 00  op_LessThan
		$a_01_8 = {67 65 74 5f 4e 6f 77 } //01 00  get_Now
		$a_01_9 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_10 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_11 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}