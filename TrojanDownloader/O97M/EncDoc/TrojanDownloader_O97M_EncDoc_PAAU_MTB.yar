
rule TrojanDownloader_O97M_EncDoc_PAAU_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 33 35 30 32 34 66 74 63 6f 70 65 6e 67 61 67 65 6e 64 73 74 77 65 62 63 6c 69 65 65 6d 6e 74 6e 65 6b 61 6d 6d 65 72 6c 6f 61 66 66 64 6f 77 6e 6c 6f 61 64 66 69 } //01 00  135024ftcopengagendstwebclieemntnekammerloaffdownloadfi
		$a_01_1 = {64 6f 73 6c 65 65 70 32 35 32 30 31 66 6f 62 6a 65 63 74 6e 65 77 } //01 00  dosleep25201fobjectnew
		$a_01_2 = {74 68 65 6e 73 68 65 6c 6c 6d 69 6c 6c 65 72 62 65 65 72 6c 6f 73 74 } //00 00  thenshellmillerbeerlost
	condition:
		any of ($a_*)
 
}