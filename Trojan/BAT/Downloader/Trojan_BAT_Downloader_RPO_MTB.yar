
rule Trojan_BAT_Downloader_RPO_MTB{
	meta:
		description = "Trojan:BAT/Downloader.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 00 6f 00 70 00 34 00 74 00 6f 00 70 00 2e 00 69 00 6f 00 90 02 20 2e 00 6a 00 70 00 67 00 90 00 } //01 00 
		$a_01_1 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00  Invoke
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {54 68 72 65 61 64 } //01 00  Thread
		$a_01_5 = {47 65 74 52 65 73 70 6f 6e 73 65 } //01 00  GetResponse
		$a_01_6 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}