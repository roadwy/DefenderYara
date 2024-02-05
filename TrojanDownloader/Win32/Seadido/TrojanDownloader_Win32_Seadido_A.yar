
rule TrojanDownloader_Win32_Seadido_A{
	meta:
		description = "TrojanDownloader:Win32/Seadido.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 50 56 ff d3 6a 00 6a 00 68 40 04 00 00 56 ff d7 } //01 00 
		$a_03_1 = {6a 1a 50 6a 00 ff 15 90 01 04 8d 4c 24 08 51 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}