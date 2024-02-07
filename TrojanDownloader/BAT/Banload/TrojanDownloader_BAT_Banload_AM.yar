
rule TrojanDownloader_BAT_Banload_AM{
	meta:
		description = "TrojanDownloader:BAT/Banload.AM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 69 00 6c 00 6c 00 69 00 6f 00 6e 00 63 00 61 00 72 00 72 00 6f 00 73 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 63 00 61 00 72 00 73 00 68 00 64 00 62 00 66 00 76 00 2e 00 7a 00 69 00 70 00 } //00 00  http://millioncarros.com.br/carshdbfv.zip
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Banload_AM_2{
	meta:
		description = "TrojanDownloader:BAT/Banload.AM,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 08 00 00 0a 00 "
		
	strings :
		$a_03_0 = {4c 00 61 00 62 00 65 00 6c 00 32 00 90 02 08 68 00 74 00 74 00 70 00 90 02 02 3a 00 2f 00 2f 00 90 00 } //0a 00 
		$a_01_1 = {76 00 65 00 6e 00 74 00 78 00 2e 00 7a 00 69 00 70 00 } //0a 00  ventx.zip
		$a_03_2 = {4e 00 61 00 6d 00 65 00 53 00 70 00 61 00 63 00 65 00 90 01 06 90 02 06 2e 00 7a 00 69 00 70 00 90 01 02 90 02 02 43 00 6f 00 70 00 79 00 48 00 65 00 72 00 65 00 90 00 } //01 00 
		$a_01_3 = {55 6e 5a 69 70 00 73 65 74 5f 54 61 62 53 74 6f 70 00 } //01 00  湕楚p敳彴慔卢潴p
		$a_01_4 = {53 6c 65 65 70 00 73 65 74 5f 54 61 62 53 74 6f 70 00 } //01 00  汓敥p敳彴慔卢潴p
		$a_01_5 = {52 69 70 00 73 65 74 5f 54 61 62 53 74 6f 70 00 } //01 00  楒p敳彴慔卢潴p
		$a_01_6 = {42 6f 78 38 00 73 65 74 5f 54 61 62 53 74 6f 70 00 } //01 00 
		$a_01_7 = {78 7a 63 76 00 73 65 74 5f 54 61 62 49 6e 64 65 78 00 } //00 00  穸癣猀瑥呟扡湉敤x
		$a_00_8 = {5d 04 00 00 ff 6c 03 80 5c 24 00 } //00 00 
	condition:
		any of ($a_*)
 
}