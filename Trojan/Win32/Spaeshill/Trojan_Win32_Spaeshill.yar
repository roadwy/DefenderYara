
rule Trojan_Win32_Spaeshill{
	meta:
		description = "Trojan:Win32/Spaeshill,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 67 61 6d 65 73 2f 68 69 6c 6c 2e 70 68 70 3f 63 49 64 3d 25 73 } //03 00  GET /games/hill.php?cId=%s
		$a_01_1 = {47 45 54 20 2f 67 61 6d 65 73 2f 64 6f 77 6e 2e 70 68 70 3f 63 49 64 3d 25 73 } //03 00  GET /games/down.php?cId=%s
		$a_01_2 = {50 72 6f 6a 65 63 74 73 5c 44 6f 77 6e 57 69 6e 33 32 5c 52 65 6c 65 61 73 65 5c 44 6f 77 6e 57 69 6e 33 32 2e 70 64 62 } //01 00  Projects\DownWin32\Release\DownWin32.pdb
		$a_01_3 = {5c 00 49 00 6e 00 74 00 65 00 6c 00 20 00 43 00 68 00 69 00 70 00 73 00 65 00 74 00 2e 00 6c 00 6e 00 6b 00 } //01 00  \Intel Chipset.lnk
		$a_01_4 = {44 00 6f 00 77 00 6e 00 57 00 69 00 6e 00 33 00 32 00 } //01 00  DownWin32
		$a_81_5 = {73 70 6c 73 72 76 2e 65 78 65 } //00 00  splsrv.exe
		$a_00_6 = {5d 04 00 00 46 6a } //03 80 
	condition:
		any of ($a_*)
 
}