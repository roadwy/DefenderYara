
rule TrojanDownloader_Win32_Banload_NW{
	meta:
		description = "TrojanDownloader:Win32/Banload.NW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 6f 6d 69 6e 69 6f 74 65 6d 70 6f 72 61 72 69 6f 2e 63 6f 6d 2f } //01 00  .dominiotemporario.com/
		$a_02_1 = {68 98 3a 00 00 e8 90 01 03 ff 8d 90 01 02 8b 90 01 02 8b 90 01 02 e8 90 01 03 ff 8b 90 01 02 e8 90 01 04 84 c0 74 90 01 01 6a 00 8d 90 01 02 8b 90 01 02 8b 90 01 02 e8 90 01 03 ff 8b 90 01 02 e8 90 01 03 ff 50 e8 90 00 } //01 00 
		$a_00_2 = {6e 65 74 62 65 61 6e 73 5f 64 62 5c } //00 00  netbeans_db\
	condition:
		any of ($a_*)
 
}