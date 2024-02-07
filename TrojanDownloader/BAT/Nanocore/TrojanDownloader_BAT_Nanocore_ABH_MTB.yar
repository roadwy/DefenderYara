
rule TrojanDownloader_BAT_Nanocore_ABH_MTB{
	meta:
		description = "TrojanDownloader:BAT/Nanocore.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {07 08 07 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 07 17 6f 90 01 03 0a 06 07 6f 90 01 03 0a 17 73 90 01 03 0a 0d 09 02 16 02 8e 69 6f 90 01 03 0a de 0a 09 2c 06 09 6f 90 01 03 0a dc 06 6f 90 01 03 0a 13 04 de 4b 90 00 } //01 00 
		$a_01_1 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //01 00  Rfc2898DeriveBytes
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}