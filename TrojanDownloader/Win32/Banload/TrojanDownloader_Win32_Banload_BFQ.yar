
rule TrojanDownloader_Win32_Banload_BFQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFQ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 61 73 69 6f 61 68 66 73 61 76 78 31 38 35 32 37 33 31 } //0a 00  casioahfsavx1852731
		$a_01_1 = {61 66 76 63 78 6f 75 65 72 69 75 76 63 78 39 38 33 34 32 38 33 } //0a 00  afvcxoueriuvcx9834283
		$a_01_2 = {6d 7a 69 75 73 64 30 39 38 33 32 35 33 34 37 35 7a 7a 71 65 } //01 00  mziusd0983253475zzqe
		$a_03_3 = {84 c0 75 0a a1 90 01 04 e8 90 01 03 ff b8 90 01 04 ba 90 01 04 e8 90 01 03 ff b8 90 01 04 b9 90 01 04 8b 15 90 01 04 e8 90 01 03 ff b8 90 01 04 b9 90 01 04 8b 15 90 01 04 e8 90 01 03 ff 90 00 } //01 00 
		$a_03_4 = {84 c0 75 07 8b 03 e8 90 01 03 ff b8 90 01 04 ba 90 01 04 e8 90 01 03 ff b8 90 01 04 b9 90 01 04 8b 13 e8 90 01 03 ff b8 90 01 04 b9 90 01 04 8b 13 e8 90 01 03 ff b8 90 01 04 b9 90 01 04 8b 13 90 00 } //00 00 
		$a_00_5 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}