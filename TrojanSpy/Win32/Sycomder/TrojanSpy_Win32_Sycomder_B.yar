
rule TrojanSpy_Win32_Sycomder_B{
	meta:
		description = "TrojanSpy:Win32/Sycomder.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 2e 64 61 74 } //02 00  sys.dat
		$a_01_1 = {7b 42 55 46 46 45 52 20 42 45 47 49 4e 7d } //02 00  {BUFFER BEGIN}
		$a_01_2 = {7b 43 6f 6e 74 69 6e 75 65 21 7d } //02 00  {Continue!}
		$a_01_3 = {7b 52 69 67 68 74 7d } //03 00  {Right}
		$a_01_4 = {5c 61 75 74 6f 69 6e 73 74 61 6c 6c 2e 65 78 65 } //00 00  \autoinstall.exe
		$a_00_5 = {7e 15 00 00 fe } //bb 07 
	condition:
		any of ($a_*)
 
}