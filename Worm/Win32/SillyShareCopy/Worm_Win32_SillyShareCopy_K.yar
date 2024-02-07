
rule Worm_Win32_SillyShareCopy_K{
	meta:
		description = "Worm:Win32/SillyShareCopy.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 65 72 69 66 65 72 69 63 6f 20 43 6f 6e 65 63 74 61 64 6f 21 } //01 00  Periferico Conectado!
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {5b 41 75 74 6f 72 75 6e 5d } //01 00  [Autorun]
		$a_01_3 = {00 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 } //00 00 
	condition:
		any of ($a_*)
 
}