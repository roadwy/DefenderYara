
rule TrojanDownloader_BAT_Aentdwn_C_bit{
	meta:
		description = "TrojanDownloader:BAT/Aentdwn.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 67 00 2e 00 6c 00 6f 00 67 00 } //01 00  log.log
		$a_03_1 = {6e 00 6e 00 6a 00 61 00 2e 00 70 00 77 00 2f 00 90 02 2f 69 00 6e 00 64 00 65 00 78 00 5f 00 76 00 32 00 2e 00 70 00 68 00 70 00 90 00 } //01 00 
		$a_01_2 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 4d 00 61 00 73 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  DownloadMaster.exe
	condition:
		any of ($a_*)
 
}