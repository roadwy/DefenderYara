
rule Backdoor_Win32_Garex_A_dha{
	meta:
		description = "Backdoor:Win32/Garex.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 04 00 "
		
	strings :
		$a_00_0 = {50 53 53 53 c6 45 e8 42 c6 45 e9 6b c6 45 ea 61 c6 45 eb 76 c6 45 ec 46 c6 45 ed 69 c6 45 ee 72 c6 45 ef 65 c6 45 f0 77 c6 45 f1 61 c6 45 f2 6c c6 45 f3 6c c6 45 f4 53 c6 45 f5 65 c6 45 f6 72 c6 45 f7 76 c6 45 f8 65 c6 45 f9 72 88 5d fa ff d6 3b c3 } //04 00 
		$a_00_1 = {8b 13 8b ca 8b f2 c1 e9 1d c1 ee 1e 8b fa 83 e1 01 83 e6 01 c1 ef 1f f7 c2 00 00 00 02 } //02 00 
		$a_01_2 = {50 79 74 68 6f 6e 54 68 72 65 61 64 53 74 61 72 74 } //02 00  PythonThreadStart
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 52 65 70 6f 72 74 69 6e 67 } //02 00  SOFTWARE\Microsoft\Windows Update Reporting
		$a_01_4 = {7b 36 37 42 44 45 35 44 37 2d 43 32 46 43 2d 38 38 39 38 2d 39 30 39 36 2d 43 32 35 35 41 42 37 39 31 42 37 35 7d } //02 00  {67BDE5D7-C2FC-8898-9096-C255AB791B75}
		$a_01_5 = {7b 41 43 36 33 34 30 32 38 2d 39 42 46 32 2d 34 61 36 38 2d 38 43 39 33 2d 46 35 31 35 44 41 38 39 33 37 37 39 7d } //00 00  {AC634028-9BF2-4a68-8C93-F515DA893779}
		$a_00_6 = {5d 04 00 00 fd } //32 03 
	condition:
		any of ($a_*)
 
}