
rule TrojanDownloader_Win32_Genome_AA{
	meta:
		description = "TrojanDownloader:Win32/Genome.AA,SIGNATURE_TYPE_PEHSTR,06 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 31 34 30 2e 63 6f 2e 6b 72 } //01 00  1140.co.kr
		$a_01_1 = {6c 6f 63 61 6c 2e 31 31 34 30 2e 63 6f 2e 6b 72 } //01 00  local.1140.co.kr
		$a_01_2 = {69 6e 67 72 69 64 2e 65 78 65 } //01 00  ingrid.exe
		$a_01_3 = {69 6e 67 72 69 64 5f 75 70 64 61 74 65 2e 65 78 65 } //01 00  ingrid_update.exe
		$a_01_4 = {69 6e 67 72 69 64 5f 64 65 6c 65 74 65 2e 65 78 65 } //01 00  ingrid_delete.exe
		$a_01_5 = {61 78 41 64 42 61 72 50 72 6f 6a 31 2e 6f 63 78 } //01 00  axAdBarProj1.ocx
		$a_01_6 = {57 69 6e 64 6f 77 73 20 31 31 34 6b 74 69 } //00 00  Windows 114kti
	condition:
		any of ($a_*)
 
}