
rule TrojanDropper_Win32_Zegost_E{
	meta:
		description = "TrojanDropper:Win32/Zegost.E,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 08 00 00 04 00 "
		
	strings :
		$a_03_0 = {57 68 00 00 40 06 c7 44 24 14 00 00 00 00 c7 44 24 28 00 00 40 06 e8 90 01 04 8b 4c 24 28 8b f0 8b d1 33 c0 8b fe 53 c1 e9 02 f3 ab 8b ca 90 00 } //04 00 
		$a_03_1 = {8b c8 81 e1 01 00 00 80 79 90 01 01 49 83 c9 fe 41 8a 0c 30 74 90 01 01 80 c1 0d eb 90 01 01 80 c1 fe 88 0c 30 8b 4c 24 20 40 3b c1 90 00 } //04 00 
		$a_01_2 = {8d 7c 24 6c 83 c9 ff 33 c0 8d 94 24 ac 00 00 00 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 ff d3 } //01 00 
		$a_01_3 = {2e 6a 70 67 } //01 00  .jpg
		$a_01_4 = {69 61 6d 73 6c 65 65 70 69 6e 67 } //01 00  iamsleeping
		$a_01_5 = {6c 6b 6e 78 6f 74 64 } //01 00  lknxotd
		$a_01_6 = {46 64 72 31 33 38 69 70 32 } //01 00  Fdr138ip2
		$a_01_7 = {73 67 66 64 66 64 73 35 38 72 } //00 00  sgfdfds58r
	condition:
		any of ($a_*)
 
}