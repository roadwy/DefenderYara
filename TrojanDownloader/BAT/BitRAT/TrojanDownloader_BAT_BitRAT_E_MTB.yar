
rule TrojanDownloader_BAT_BitRAT_E_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 00 0a 25 02 6f 90 01 01 00 00 0a 0a 6f 90 01 01 00 00 0a 06 0b de 90 00 } //01 00 
		$a_03_1 = {06 8e 69 8d 90 01 01 00 00 01 0c 16 0d 2b 90 00 } //01 00 
		$a_01_2 = {08 09 07 09 07 8e 69 5d 91 06 09 91 61 d2 9c } //01 00 
		$a_01_3 = {67 65 74 5f 41 53 43 49 49 } //01 00  get_ASCII
		$a_01_4 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_5 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}