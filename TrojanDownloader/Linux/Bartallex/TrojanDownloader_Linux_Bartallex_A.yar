
rule TrojanDownloader_Linux_Bartallex_A{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 34 34 2f 75 70 64 2f 69 6e 73 74 61 6c 6c } //01 00  .44/upd/install
		$a_01_1 = {3a 2f 2f 39 31 2e 32 32 30 2e 31 33 31 } //00 00  ://91.220.131
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_A_2{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.A,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 33 35 2f 75 70 64 2f 69 6e 73 74 61 6c 6c } //01 00  .35/upd/install
		$a_01_1 = {3a 2f 2f 31 34 36 2e 31 38 35 2e 32 31 33 } //00 00  ://146.185.213
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_A_3{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 41 52 54 20 3d 20 22 22 20 2b 20 42 41 52 54 32 } //01 00  BART = "" + BART2
		$a_00_1 = {4b 69 6c 6c 20 58 50 46 49 4c 45 44 49 52 } //01 00  Kill XPFILEDIR
		$a_00_2 = {22 63 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 22 } //01 00  "c:\Windows\Temp"
		$a_02_3 = {53 75 62 20 41 75 74 6f 90 02 02 4f 70 65 6e 28 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_A_4{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 39 31 2e 32 32 30 2e 31 33 31 } //01 00  ://91.220.131
		$a_03_1 = {2f 75 70 64 90 02 01 2f 69 6e 73 74 61 6c 6c 90 00 } //01 00 
		$a_00_2 = {22 63 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 22 20 2b 20 42 41 52 54 } //01 00  "c:\Windows\Temp\" + BART
		$a_01_3 = {4b 69 6c 6c 20 58 50 46 49 4c 45 44 49 52 } //01 00  Kill XPFILEDIR
		$a_00_4 = {42 41 52 54 20 3d 20 22 22 20 2b 20 42 41 52 54 32 20 2b 20 43 68 72 } //00 00  BART = "" + BART2 + Chr
		$a_00_5 = {8f a7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Linux_Bartallex_A_5{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 28 41 73 63 28 43 68 72 28 41 73 63 28 22 68 22 29 29 29 29 20 2b 20 43 68 72 28 41 73 63 28 43 68 72 28 41 73 63 28 22 74 22 29 29 29 29 20 2b 20 43 68 72 28 41 73 63 28 22 74 22 29 29 20 2b 20 43 68 72 28 41 73 63 28 43 68 72 28 41 73 63 28 22 70 22 29 29 29 29 20 2b 20 22 3a 2f 2f } //01 00  Chr(Asc(Chr(Asc("h")))) + Chr(Asc(Chr(Asc("t")))) + Chr(Asc("t")) + Chr(Asc(Chr(Asc("p")))) + "://
		$a_01_1 = {22 2e 65 22 20 26 20 22 78 22 20 2b 20 22 65 27 3b } //01 00  ".e" & "x" + "e';
		$a_01_2 = {6f 62 6a 58 4d 4c 48 54 54 50 } //01 00  objXMLHTTP
		$a_01_3 = {6f 62 6a 41 44 4f 53 74 72 65 61 6d 2e 4f 70 65 6e } //00 00  objADOStream.Open
	condition:
		any of ($a_*)
 
}