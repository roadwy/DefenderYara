
rule TrojanDownloader_Win32_Banload_YI{
	meta:
		description = "TrojanDownloader:Win32/Banload.YI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {51 00 75 00 65 00 49 00 73 00 73 00 6f 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  QueIsso\Project1.vbp
		$a_02_1 = {2e 00 73 00 77 00 66 00 90 02 10 5c 00 77 00 69 00 6e 00 73 00 63 00 6b 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}