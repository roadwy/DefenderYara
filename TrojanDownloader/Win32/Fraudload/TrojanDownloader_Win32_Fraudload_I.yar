
rule TrojanDownloader_Win32_Fraudload_I{
	meta:
		description = "TrojanDownloader:Win32/Fraudload.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b ff 55 8d 4a 64 51 b9 40 00 00 00 51 ba 00 10 00 00 52 bf 80 05 00 00 57 bb 00 00 00 00 53 e8 7b 02 00 00 59 89 41 d0 8d b8 56 ff ff ff bb 36 10 40 00 33 f6 81 fe 80 05 00 00 74 28 83 c6 04 83 c3 04 8b 43 fc 89 87 aa 00 00 00 83 c7 04 81 87 a6 00 00 00 46 8e 1f d4 81 b7 a6 00 00 00 5c 2a 74 4e eb d0 } //01 00 
		$a_00_1 = {92 f2 80 c3 48 26 b6 0f 1a 4c 2a 1e cc b5 f9 1b a3 50 9e 53 f4 70 26 6b ef 61 } //01 00 
		$a_00_2 = {81 76 08 8b 4e 86 d9 23 d7 fb ff 00 f4 08 e0 65 dc 56 7b 1d fe 3e b9 b9 } //00 00 
	condition:
		any of ($a_*)
 
}