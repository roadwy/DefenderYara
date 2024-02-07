
rule TrojanDropper_Win32_Monkif_F{
	meta:
		description = "TrojanDropper:Win32/Monkif.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49 } //01 00 
		$a_01_1 = {81 7d f4 93 08 00 00 74 0c 46 81 fe e8 19 10 00 7c e4 } //01 00 
		$a_03_2 = {8d 48 fe 81 f9 90 01 04 7c c7 90 00 } //01 00 
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 50 52 2e 54 4f 43 4f 4c 53 5c 46 69 6c 74 65 72 5c 74 65 78 74 2f 68 74 6d 6c 00 } //01 00  潓瑦慷敲䍜慬獳獥停⹒佔佃卌䙜汩整屲整瑸栯浴l
		$a_01_4 = {b8 68 58 4d 56 b9 14 00 00 00 66 ba 58 56 ed } //00 00 
	condition:
		any of ($a_*)
 
}