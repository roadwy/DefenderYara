
rule TrojanDownloader_Win32_Carrot_A_ibt{
	meta:
		description = "TrojanDownloader:Win32/Carrot.A!ibt,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {78 7a 2e 64 61 73 68 69 38 38 2e 63 6f 6d } //01 00  xz.dashi88.com
		$a_01_1 = {2f 63 61 72 72 6f 74 2e 69 6e 69 } //01 00  /carrot.ini
		$a_01_2 = {73 68 6f 72 74 72 6f 75 6e 64 2e 70 64 62 } //01 00  shortround.pdb
		$a_01_3 = {73 65 64 65 62 75 67 70 72 69 76 69 6c 65 67 65 } //01 00  sedebugprivilege
		$a_01_4 = {5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 73 6f 6e 74 61 67 } //01 00  \windows\currentversion\sontag
		$a_01_5 = {66 6c 6f 77 65 72 79 6c 69 66 65 } //00 00  flowerylife
	condition:
		any of ($a_*)
 
}