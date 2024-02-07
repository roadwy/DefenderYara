
rule TrojanDownloader_Win32_Banload_AAG{
	meta:
		description = "TrojanDownloader:Win32/Banload.AAG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 6b 61 72 6c 61 2d 73 61 72 61 69 76 61 2e } //01 00  /karla-saraiva.
		$a_01_1 = {68 74 74 70 3a 2f 2f 67 61 74 61 } //01 00  http://gata
		$a_01_2 = {2f 67 61 74 61 90 01 05 2e 6a 70 67 } //01 00 
		$a_01_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 67 61 74 61 } //03 00  c:\windows\gata
		$a_03_4 = {63 6d 64 20 2f 6b 20 63 3a 90 01 01 77 69 6e 64 6f 77 73 90 01 01 73 79 73 74 65 6d 33 32 90 02 07 2e 63 70 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}