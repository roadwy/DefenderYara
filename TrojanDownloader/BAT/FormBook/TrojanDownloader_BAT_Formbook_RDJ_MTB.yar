
rule TrojanDownloader_BAT_Formbook_RDJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 71 69 78 6a 79 68 6e 63 6f 61 66 69 69 } //01 00  Xqixjyhncoafii
		$a_01_1 = {4c 74 7a 6d 79 6b 6d 65 6a 74 79 63 } //01 00  Ltzmykmejtyc
		$a_01_2 = {59 75 71 6e 64 61 7a 67 6d 71 6f 63 } //01 00  Yuqndazgmqoc
		$a_01_3 = {39 62 35 61 39 61 39 63 38 31 66 37 34 31 61 37 32 33 34 63 61 33 62 61 61 65 36 32 64 63 35 36 } //00 00  9b5a9a9c81f741a7234ca3baae62dc56
	condition:
		any of ($a_*)
 
}