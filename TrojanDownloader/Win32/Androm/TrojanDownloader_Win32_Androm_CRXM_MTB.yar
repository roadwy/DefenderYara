
rule TrojanDownloader_Win32_Androm_CRXM_MTB{
	meta:
		description = "TrojanDownloader:Win32/Androm.CRXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 68 00 00 40 00 6a 00 6a 00 68 90 01 03 00 50 ff 15 90 00 } //01 00 
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 62 61 79 61 6e 62 6f 78 2e 69 72 2f 64 6f 77 6e 6c 6f 61 64 2f 39 39 39 31 38 36 36 32 31 31 35 38 32 35 38 31 32 32 2f 53 68 65 6c 6c 63 6f 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}