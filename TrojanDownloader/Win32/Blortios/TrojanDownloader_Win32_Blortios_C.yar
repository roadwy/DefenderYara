
rule TrojanDownloader_Win32_Blortios_C{
	meta:
		description = "TrojanDownloader:Win32/Blortios.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 2e 61 73 70 78 3f 66 69 6c 65 3d 32 } //02 00  file.aspx?file=2
		$a_01_1 = {62 6c 6f 67 64 65 63 68 61 72 75 74 6f 73 2e 63 6f 6d } //02 00  blogdecharutos.com
		$a_01_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 6b 73 70 2f 57 53 } //01 00  User-Agent: ksp/WS
		$a_01_3 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00  Referer: http://www.google.com
		$a_01_4 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 57 4c 53 65 74 75 70 } //01 00  ProgramData\WLSetup
		$a_01_5 = {56 00 62 00 50 00 51 00 52 00 53 00 54 00 55 00 2b 00 41 00 42 00 43 00 44 00 45 00 46 00 47 00 63 00 32 00 2f 00 35 00 36 00 37 00 38 00 66 00 67 00 68 00 69 00 6a 00 73 00 74 00 75 00 30 00 31 00 4d 00 6b 00 6c 00 } //00 00  VbPQRSTU+ABCDEFGc2/5678fghijstu01Mkl
	condition:
		any of ($a_*)
 
}