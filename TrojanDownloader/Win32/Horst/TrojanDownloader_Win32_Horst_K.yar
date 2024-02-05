
rule TrojanDownloader_Win32_Horst_K{
	meta:
		description = "TrojanDownloader:Win32/Horst.K,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 04 01 00 00 68 50 ac 40 00 68 90 01 02 40 00 ff 15 90 01 01 80 40 00 90 03 0b 06 90 02 02 ff d6 68 90 01 02 40 00 68 90 01 02 40 00 90 00 } //01 00 
		$a_02_1 = {68 04 01 00 00 68 30 ac 40 00 68 90 01 02 40 00 ff 15 90 01 01 80 40 00 ff d6 68 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}