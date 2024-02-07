
rule TrojanSpy_Win32_Upolid_A{
	meta:
		description = "TrojanSpy:Win32/Upolid.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 53 00 68 00 65 00 6c 00 6c 00 55 00 70 00 64 00 61 00 74 00 65 00 2e 00 6c 00 6e 00 6b 00 } //01 00  WinShellUpdate.lnk
		$a_01_1 = {2f 00 73 00 63 00 72 00 65 00 65 00 6e 00 53 00 68 00 6f 00 74 00 } //01 00  /screenShot
		$a_01_2 = {74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 20 00 3e 00 20 00 22 00 } //01 00  tasklist > "
		$a_01_3 = {2f 00 77 00 68 00 69 00 74 00 65 00 5f 00 77 00 61 00 6c 00 6b 00 65 00 72 00 73 00 2f 00 } //01 00  /white_walkers/
		$a_01_4 = {5c 00 73 00 66 00 6c 00 61 00 67 00 2e 00 74 00 78 00 74 00 } //00 00  \sflag.txt
		$a_00_5 = {5d 04 00 } //00 da 
	condition:
		any of ($a_*)
 
}