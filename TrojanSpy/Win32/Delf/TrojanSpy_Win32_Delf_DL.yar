
rule TrojanSpy_Win32_Delf_DL{
	meta:
		description = "TrojanSpy:Win32/Delf.DL,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 09 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 4c 69 76 65 3a 6e 61 6d 65 3d 2a } //05 00  WindowsLive:name=*
		$a_01_1 = {49 6d 52 65 6d 6f 74 65 4b 65 79 6c 6f 67 67 65 72 24 24 46 69 6e 69 73 68 } //01 00  ImRemoteKeylogger$$Finish
		$a_01_2 = {5b 42 41 43 4b 53 50 41 43 45 5d } //01 00  [BACKSPACE]
		$a_01_3 = {5b 54 61 62 5d } //01 00  [Tab]
		$a_01_4 = {5b 44 65 6c 5d } //01 00  [Del]
		$a_01_5 = {2a 55 73 65 72 6e 61 6d 65 2a 3a 20 } //01 00  *Username*: 
		$a_01_6 = {2a 50 61 73 73 77 6f 72 64 2a 3a 20 } //01 00  *Password*: 
		$a_01_7 = {56 65 72 73 69 6f 6e 65 20 64 69 20 57 69 6e 64 6f 77 73 3a 20 40 40 } //01 00  Versione di Windows: @@
		$a_01_8 = {56 65 72 73 69 6f 6e 65 20 64 65 6c 20 73 65 72 76 65 72 3a 20 40 40 } //00 00  Versione del server: @@
	condition:
		any of ($a_*)
 
}