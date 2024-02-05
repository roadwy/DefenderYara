
rule TrojanDownloader_Win32_Adload_BB{
	meta:
		description = "TrojanDownloader:Win32/Adload.BB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 2d 6d 79 64 61 74 65 2e 70 68 70 00 00 00 73 6f 66 74 77 61 72 65 5c } //01 00 
		$a_01_1 = {2d 6d 79 00 74 6f 74 61 6c 00 00 00 5c 54 65 6d 70 5c 00 00 4e 69 6e 66 6f 2e 64 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}