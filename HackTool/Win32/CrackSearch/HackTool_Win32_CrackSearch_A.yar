
rule HackTool_Win32_CrackSearch_A{
	meta:
		description = "HackTool:Win32/CrackSearch.A,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 68 00 65 00 20 00 4e 00 65 00 78 00 74 00 20 00 47 00 65 00 6e 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00 20 00 3b 00 2d 00 29 00 } //01 00  The Next Generation Search Engine ;-)
		$a_01_1 = {59 00 6f 00 75 00 4b 00 69 00 6e 00 67 00 20 00 32 00 30 00 30 00 35 00 } //01 00  YouKing 2005
		$a_01_2 = {70 72 6f 78 79 2e 74 78 74 } //01 00  proxy.txt
		$a_01_3 = {43 6f 76 65 72 73 41 6c 6c } //01 00  CoversAll
		$a_01_4 = {43 72 61 63 6b 73 41 6c 6c } //01 00  CracksAll
		$a_01_5 = {53 65 72 69 61 6c 73 41 6c 6c } //01 00  SerialsAll
		$a_01_6 = {64 72 65 61 6d 63 61 73 74 } //01 00  dreamcast
		$a_01_7 = {67 61 6d 65 63 75 62 65 } //01 00  gamecube
		$a_01_8 = {45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a } //01 00  Extended Module:
		$a_01_9 = {43 72 61 61 67 6c 65 55 74 69 6c 73 } //01 00  CraagleUtils
		$a_01_10 = {50 72 6f 78 79 3a } //00 00  Proxy:
	condition:
		any of ($a_*)
 
}