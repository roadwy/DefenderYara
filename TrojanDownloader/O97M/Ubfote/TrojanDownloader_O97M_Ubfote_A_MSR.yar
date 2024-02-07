
rule TrojanDownloader_O97M_Ubfote_A_MSR{
	meta:
		description = "TrojanDownloader:O97M/Ubfote.A!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //01 00  Private Sub Document_Open()
		$a_00_1 = {73 43 6d 64 4c 69 6e 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 77 69 6e 64 69 72 22 29 } //01 00  sCmdLine = Environ("windir")
		$a_02_2 = {73 43 6d 64 4c 69 6e 65 20 3d 20 73 43 6d 64 4c 69 6e 65 20 90 02 0b 54 65 78 74 42 6f 78 31 2e 54 65 78 74 90 00 } //01 00 
		$a_00_3 = {53 68 65 6c 6c 28 73 43 6d 64 4c 69 6e 65 2c 20 76 62 48 69 64 65 29 } //00 00  Shell(sCmdLine, vbHide)
	condition:
		any of ($a_*)
 
}