
rule TrojanDownloader_O97M_Donoff_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 72 65 69 32 2e } //01 00  = "tps://www.diamantesviagens.com.br/rei2.
		$a_01_1 = {3d 20 22 68 74 61 22 22 20 68 74 22 } //00 00  = "hta"" ht"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_RA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 72 72 61 79 6d 61 69 6e 28 69 29 2e 64 61 74 65 5f 62 6f 72 72 6f 77 65 64 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e } //01 00  arraymain(i).date_borrowed = "https://www.
		$a_01_1 = {61 72 72 61 79 6d 61 69 6e 28 69 29 2e 64 61 74 65 5f 64 75 65 20 3d 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 68 61 73 64 6f 6f 6b 64 6b 77 64 69 61 68 73 69 64 68 } //00 00  arraymain(i).date_due = "bitly.com/asdhasdookdkwdiahsidh
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_RA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 31 20 3d 20 22 65 63 68 22 20 2b 20 22 6f 20 73 74 61 72 74 22 20 26 20 22 20 63 61 22 0d 0a 63 6f 6d 32 20 3d 20 22 6c 63 20 3e 3e 20 25 74 65 6d 70 25 5c 32 2e 74 78 74 22 0d 0a 63 6f 6d 33 20 3d 20 63 6f 6d 31 20 2b 20 63 6f 6d 32 } //01 00 
		$a_01_1 = {53 65 74 20 6f 62 6a 73 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //00 00  Set objshell = CreateObject("wscript.shell")
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_RA_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4e 65 77 4d 61 63 72 6f 73 22 } //01 00  Attribute VB_Name = "NewMacros"
		$a_03_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a 90 02 0a 64 65 62 75 67 4d 61 63 72 6f 44 6f 77 6e 6c 6f 61 64 0d 0a 90 02 0a 4d 79 4d 61 63 72 6f 0d 0a 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_2 = {61 64 64 72 20 3d 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 28 30 2c 20 55 42 6f 75 6e 64 28 62 75 66 29 2c 20 26 48 33 30 30 30 2c 20 26 48 34 30 29 } //01 00  addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
		$a_01_3 = {72 65 73 20 3d 20 43 72 65 61 74 65 54 68 72 65 61 64 28 30 2c 20 30 2c 20 61 64 64 72 2c 20 30 2c 20 30 2c 20 30 29 } //01 00  res = CreateThread(0, 0, addr, 0, 0, 0)
		$a_03_4 = {31 39 32 2e 31 36 38 2e 34 39 2e 37 39 2f 44 45 42 55 47 5f 44 4f 57 4e 4c 4f 41 44 20 74 65 73 74 2e 74 78 74 22 2c 20 76 62 48 69 64 65 29 90 0a 9f 00 3d 20 53 68 65 6c 6c 28 22 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 68 74 74 70 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Donoff_RA_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 41 75 74 6f 43 6c 6f 73 65 28 29 0d 0a 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 90 02 1f 22 0d 0a 45 6e 64 20 53 75 62 0d 0a 50 75 62 6c 69 63 20 53 75 62 20 90 1b 00 28 29 90 00 } //01 00 
		$a_03_1 = {44 69 6d 20 90 02 1f 0d 0a 90 1b 00 20 3d 20 22 68 65 6c 6c 6f 22 90 00 } //01 00 
		$a_03_2 = {53 65 74 20 90 02 1f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 0d 0a 90 02 0f 90 1b 00 2e 52 75 6e 20 90 02 2f 2c 20 30 0d 0a 90 02 0f 4c 6f 6f 70 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //01 00 
		$a_03_3 = {53 65 74 20 90 02 1f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 73 78 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 2e 33 2e 30 22 29 0d 0a 53 65 74 20 90 02 1f 20 3d 20 90 1b 00 2e 43 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 61 73 65 36 34 22 29 90 00 } //01 00 
		$a_01_4 = {2e 64 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //01 00  .dataType = "bin.base64"
		$a_03_5 = {44 69 6d 20 90 02 1f 0d 0a 90 02 0f 44 6f 20 57 68 69 6c 65 20 90 1b 00 20 3c 20 32 30 0d 0a 90 02 0f 90 1b 00 20 3d 20 90 1b 00 20 2b 20 31 0d 0a 90 02 0f 49 66 20 90 1b 00 20 3d 20 32 20 54 68 65 6e 20 45 78 69 74 20 44 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}