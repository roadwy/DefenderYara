
rule Trojan_BAT_AsyncRAT_ABK_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 06 06 28 90 01 03 0a 0a 72 90 01 03 70 0b 72 90 01 03 70 25 28 90 01 03 0a 26 72 90 01 03 70 0c 72 90 01 03 70 0d 06 06 28 90 01 03 0a 0d 09 28 90 01 03 0a 09 09 28 90 01 03 0a 0d 72 90 01 03 70 13 04 90 00 } //01 00 
		$a_01_1 = {48 74 74 70 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  HttpDownloadFile
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_3 = {44 65 6c 65 74 65 44 69 72 65 63 74 6f 72 79 } //01 00  DeleteDirectory
		$a_01_4 = {70 00 6f 00 77 00 65 00 72 00 6d 00 6f 00 6e 00 73 00 74 00 65 00 72 00 } //00 00  powermonster
	condition:
		any of ($a_*)
 
}