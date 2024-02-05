
rule TrojanDownloader_Win32_Dadobra_BS{
	meta:
		description = "TrojanDownloader:Win32/Dadobra.BS,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //02 00 
		$a_01_1 = {31 39 30 2e 33 34 2e 31 33 36 2e 31 38 30 2f } //01 00 
		$a_01_2 = {5c 77 69 6e 64 6f 77 73 75 70 64 61 74 65 33 32 2e 65 78 65 } //01 00 
		$a_01_3 = {5c 68 61 6e 64 6c 65 33 32 2e 65 78 65 } //01 00 
		$a_01_4 = {42 6f 6f 74 45 78 65 63 75 74 65 } //01 00 
		$a_01_5 = {46 52 4f 47 53 49 43 45 } //00 00 
	condition:
		any of ($a_*)
 
}