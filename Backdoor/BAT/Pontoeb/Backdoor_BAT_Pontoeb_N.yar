
rule Backdoor_BAT_Pontoeb_N{
	meta:
		description = "Backdoor:BAT/Pontoeb.N,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 67 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 } //01 00  /gate.php
		$a_01_1 = {77 00 73 00 63 00 6e 00 74 00 66 00 79 00 2e 00 65 00 78 00 65 00 } //01 00  wscntfy.exe
		$a_01_2 = {6c 00 73 00 6d 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  lsmass.exe
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2d 00 41 00 75 00 64 00 69 00 6f 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 } //01 00  Windows-Audio Driver
		$a_01_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2d 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 43 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 } //00 00  Windows-Network Component
	condition:
		any of ($a_*)
 
}