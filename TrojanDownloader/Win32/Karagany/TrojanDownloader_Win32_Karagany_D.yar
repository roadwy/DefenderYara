
rule TrojanDownloader_Win32_Karagany_D{
	meta:
		description = "TrojanDownloader:Win32/Karagany.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 6c 4c 72 71 74 75 68 41 33 78 30 57 6d 6a 77 4e 4d 32 37 } //01 00 
		$a_01_1 = {5c 6e 6f 72 6d 61 6c 69 7a 31 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}