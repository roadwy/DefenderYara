
rule TrojanSpy_Win32_Banker_AKW{
	meta:
		description = "TrojanSpy:Win32/Banker.AKW,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b da 3b 75 ec 7d 03 46 eb 05 be 01 00 00 00 8b 45 f0 0f b7 44 70 fe 33 d8 8d 45 cc 50 89 5d d0 } //0a 00 
		$a_01_1 = {0f b7 44 70 fe 33 c3 89 45 e4 3b 7d e4 7c 0f 8b 45 e4 05 ff 00 00 00 2b c7 89 45 e4 eb 03 29 7d e4 } //0a 00 
		$a_03_2 = {83 e8 04 8b 00 8b d8 85 db 7e 32 be 01 00 00 00 8d 45 e8 8b 15 90 01 04 0f b7 54 7a fe 8b 4d fc 0f b7 4c 71 fe 66 33 d1 90 00 } //01 00 
		$a_01_3 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 64 00 6f 00 53 00 75 00 62 00 6d 00 69 00 74 00 28 00 29 00 3b 00 00 00 } //01 00 
		$a_03_4 = {57 00 57 00 57 00 5f 00 47 00 65 00 74 00 57 00 69 00 6e 00 64 00 6f 00 77 00 49 00 6e 00 66 00 6f 00 90 01 0e 30 00 78 00 46 00 46 00 46 00 46 00 46 00 46 00 46 00 46 00 90 00 } //01 00 
		$a_01_5 = {6d 61 63 72 6f 64 69 72 65 63 74 2e 63 6f 6d 2e 61 72 2f } //01 00  macrodirect.com.ar/
		$a_01_6 = {2f 52 65 74 61 69 6c 48 6f 6d 65 42 61 6e 6b 69 6e 67 57 65 62 2f 61 63 63 65 73 73 2e 64 6f } //01 00  /RetailHomeBankingWeb/access.do
		$a_01_7 = {2f 52 65 74 61 69 6c 49 6e 73 74 69 74 75 63 69 6f 6e 61 6c 57 65 62 2f 68 6f 6d 65 2e 64 6f } //01 00  /RetailInstitucionalWeb/home.do
		$a_01_8 = {53 75 70 65 72 76 69 65 6c 6c 65 20 42 61 6e 63 6f } //01 00  Supervielle Banco
		$a_01_9 = {42 61 6e 63 6f 20 43 72 65 64 69 63 6f 6f 70 20 43 6f 6f 70 2e 20 4c 74 64 6f 2e } //01 00  Banco Credicoop Coop. Ltdo.
		$a_01_10 = {42 61 6e 63 6f 20 47 61 6c 69 63 69 61 20 2d 20 50 65 72 73 6f 6e 61 73 } //01 00  Banco Galicia - Personas
		$a_01_11 = {42 42 56 41 20 46 72 61 6e 63 c3 a9 73 } //00 00 
	condition:
		any of ($a_*)
 
}