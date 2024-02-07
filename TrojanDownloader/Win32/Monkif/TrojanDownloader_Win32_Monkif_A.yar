
rule TrojanDownloader_Win32_Monkif_A{
	meta:
		description = "TrojanDownloader:Win32/Monkif.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {83 c4 18 46 81 fe 00 00 10 00 7c e0 } //03 00 
		$a_03_1 = {83 f8 ff 74 22 90 01 01 8d 45 f4 50 6a 10 90 01 02 e8 90 01 05 8d 45 f4 50 6a 08 90 09 09 00 6a e8 90 01 01 ff 15 90 00 } //01 00 
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 50 52 4f 54 4f 43 4f 4c 53 5c 46 69 6c 74 65 72 5c 74 65 78 74 2f 68 74 6d 6c 00 } //01 00  潓瑦慷敲䍜慬獳獥停佒佔佃卌䙜汩整屲整瑸栯浴l
		$a_01_3 = {54 3d 25 64 2c 53 3d 25 64 2c 25 73 2c 46 3d 25 73 2c 00 } //02 00 
		$a_01_4 = {4c 6f 63 61 6c 5c 55 49 45 49 00 } //01 00 
		$a_01_5 = {25 75 7c 25 75 7c 25 75 7c 25 75 } //00 00  %u|%u|%u|%u
	condition:
		any of ($a_*)
 
}