
rule TrojanDownloader_O97M_BITSAbuse_C{
	meta:
		description = "TrojanDownloader:O97M/BITSAbuse.C,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {62 69 74 73 61 64 6d 69 6e } //01 00  bitsadmin
		$a_00_1 = {2f 74 72 61 6e 73 66 65 72 } //01 00  /transfer
		$a_00_2 = {2f 75 70 6c 6f 61 64 } //01 00  /upload
		$a_00_3 = {2f 64 6f 77 6e 6c 6f 61 64 } //01 00  /download
		$a_00_4 = {2f 61 64 64 66 69 6c 65 } //01 00  /addfile
		$a_00_5 = {2f 73 65 74 6e 6f 74 69 66 79 63 6d 64 6c 69 6e 65 } //00 00  /setnotifycmdline
	condition:
		any of ($a_*)
 
}