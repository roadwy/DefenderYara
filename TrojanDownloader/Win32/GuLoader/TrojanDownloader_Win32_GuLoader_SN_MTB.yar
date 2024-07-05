
rule TrojanDownloader_Win32_GuLoader_SN_MTB{
	meta:
		description = "TrojanDownloader:Win32/GuLoader.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 79 6c 6f 67 72 61 } //01 00  Xylogra
		$a_01_1 = {4e 6f 76 69 63 65 68 6f 6f } //01 00  Novicehoo
		$a_01_2 = {4f 75 74 72 61 6e 67 } //01 00  Outrang
		$a_01_3 = {42 6f 63 65 6d 65 6e 6e 65 } //01 00  Bocemenne
		$a_01_4 = {57 49 45 4e 45 52 4e 45 53 } //01 00  WIENERNES
		$a_01_5 = {4b 76 69 64 69 73 } //14 00  Kvidis
		$a_01_6 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_GuLoader_SN_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/GuLoader.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_01_1 = {46 6f 72 64 61 6e 73 6b 65 74 } //01 00  Fordansket
		$a_01_2 = {53 70 6f 72 61 6e 67 69 6f 6c 75 6d } //01 00  Sporangiolum
		$a_01_3 = {53 50 4f 52 4f 43 48 4e 55 53 } //01 00  SPOROCHNUS
		$a_01_4 = {53 54 4f 52 59 57 4f 52 4b } //01 00  STORYWORK
		$a_01_5 = {4f 55 54 52 49 44 45 52 53 } //01 00  OUTRIDERS
		$a_01_6 = {6a 6f 69 6e 74 75 72 69 6e 67 } //01 00  jointuring
		$a_01_7 = {75 64 73 75 67 65 6e 64 65 } //01 00  udsugende
		$a_01_8 = {55 6e 73 69 73 74 69 6e 67 } //01 00  Unsisting
		$a_01_9 = {53 41 4e 54 49 4e 4f 4d 45 4c 4d 4f 5a 44 } //01 00  SANTINOMELMOZD
		$a_01_10 = {4d 69 75 73 79 4c 61 54 72 6f 69 6f } //00 00  MiusyLaTroio
		$a_00_11 = {5d 04 00 00 73 3d 04 80 5c 28 00 00 74 3d 04 } //80 00 
	condition:
		any of ($a_*)
 
}