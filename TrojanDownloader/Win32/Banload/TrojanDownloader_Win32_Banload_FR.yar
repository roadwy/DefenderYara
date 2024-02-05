
rule TrojanDownloader_Win32_Banload_FR{
	meta:
		description = "TrojanDownloader:Win32/Banload.FR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {7e 2b be 01 00 00 00 8d 45 f0 8b d7 52 8b 55 fc 8a 54 32 ff 59 2a d1 f6 d2 e8 90 01 03 ff 8b 55 f0 8d 45 f4 e8 90 01 03 ff 46 4b 75 da 90 00 } //01 00 
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 65 73 73 6f 2e 65 78 65 00 } //01 00 
		$a_01_2 = {77 77 77 2e 74 6e 77 6e 65 70 61 6c 2e 6f 72 67 2f 69 6d 61 67 65 73 2f 66 6c 6f 77 65 72 2e 6a 70 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}