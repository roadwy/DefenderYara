
rule HackTool_Win32_Keygen_K{
	meta:
		description = "HackTool:Win32/Keygen.K,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 68 69 64 6f 72 61 68 40 6d 75 73 69 63 69 61 6e 2e 6f 72 67 } //02 00  ghidorah@musician.org
		$a_01_1 = {6b 65 79 67 65 6e } //02 00  keygen
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 62 61 6e 73 2e 6e 65 74 } //00 00  http://www.cobans.net
	condition:
		any of ($a_*)
 
}