
rule TrojanDownloader_BAT_Truado_AC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Truado.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 04 00 "
		
	strings :
		$a_03_0 = {13 05 20 09 90 01 02 00 28 20 90 01 02 06 3a 5a 90 01 02 00 38 55 90 01 02 00 08 28 25 90 01 02 06 28 26 90 01 02 06 73 2f 90 01 02 0a 0d 20 06 90 01 02 00 38 3a 90 01 02 00 00 72 79 90 01 02 70 72 d8 90 01 02 70 72 f0 90 01 02 70 28 21 90 01 02 06 0a 20 07 90 01 02 00 38 1a 90 01 02 00 00 07 28 24 90 01 02 06 0c 38 b8 90 01 02 ff 20 01 90 01 02 00 fe 0e 90 01 01 00 fe 0c 06 00 90 00 } //01 00 
		$a_01_1 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00  HttpWebRequest
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00  get_Assembly
	condition:
		any of ($a_*)
 
}