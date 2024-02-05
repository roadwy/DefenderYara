
rule TrojanDownloader_Win32_Sinresby_A{
	meta:
		description = "TrojanDownloader:Win32/Sinresby.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 2e 64 6c 6c 00 72 75 6e } //01 00 
		$a_03_1 = {73 69 6e 67 6c 65 00 00 00 90 01 1e 73 69 6e 67 90 00 } //01 00 
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}