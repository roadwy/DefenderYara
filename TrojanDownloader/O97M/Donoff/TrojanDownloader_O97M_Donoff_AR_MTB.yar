
rule TrojanDownloader_O97M_Donoff_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 70 6a 2e 31 63 6e 33 72 6d 33 32 39 5f 70 2f 74 65 6e 2e 70 6f 74 34 70 6f 74 2e 61 2f 2f 3a 73 70 74 74 68 } //1 gpj.1cn3rm329_p/ten.pot4pot.a//:sptth
		$a_03_1 = {53 74 72 52 65 76 65 72 73 65 28 90 02 03 65 78 65 2e 90 02 14 5c 61 74 61 44 6d 61 72 67 6f 72 50 5c 3a 43 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_AR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 74 72 52 65 76 65 72 73 65 28 22 90 02 05 61 73 6a 6b 6c 61 64 38 37 33 32 31 61 73 6a 68 64 68 61 5c 70 6d 22 20 26 20 22 2e 22 20 26 20 22 6a 5c 5c 3a 73 22 20 26 20 22 70 74 74 68 22 90 02 0f 20 61 22 20 26 20 22 74 22 20 26 20 22 68 22 20 26 20 22 73 22 20 26 20 22 6d 22 20 26 90 00 } //1
		$a_03_1 = {53 68 65 6c 6c 28 22 90 02 14 2e 65 78 65 20 22 22 43 3a 5c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_AR_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 77 22 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a 46 75 6e 63 74 69 6f 6e 20 90 02 0a 28 29 0d 0a 90 1b 00 20 3d 20 22 69 22 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 0d 0a 46 75 6e 63 74 69 6f 6e 20 90 02 0a 28 29 0d 0a 90 1b 02 20 3d 20 22 6e 22 90 00 } //2
		$a_03_1 = {28 22 20 33 20 32 20 5f 20 22 29 20 26 20 90 02 14 28 22 20 50 20 72 20 6f 20 63 20 65 20 73 20 73 20 22 29 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule TrojanDownloader_O97M_Donoff_AR_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 6e 64 5f 63 61 70 72 69 63 65 5f 61 6e 64 20 3d 20 22 6e 6f 74 65 70 61 64 20 22 } //1 and_caprice_and = "notepad "
		$a_01_1 = {29 2e 52 75 6e 28 28 61 6e 64 5f 63 61 70 72 69 63 65 5f 61 6e 64 20 26 } //1 ).Run((and_caprice_and &
		$a_01_2 = {61 73 5f 74 6f 5f 69 6e 66 6c 75 65 6e 63 65 20 3d 20 22 2e 74 78 74 22 } //1 as_to_influence = ".txt"
		$a_01_3 = {6c 65 61 76 65 5f 68 65 72 5f 75 6e 63 6c 65 20 3d 20 22 77 73 63 72 69 70 74 2e 73 68 65 6c 22 20 26 } //1 leave_her_uncle = "wscript.shel" &
		$a_01_4 = {57 73 63 72 69 70 74 2e 51 75 69 74 20 3d 20 28 22 22 20 26 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 28 6c 65 61 76 65 5f 68 65 72 5f 75 6e 63 6c 65 29 29 29 2e 52 75 6e } //1 Wscript.Quit = ("" & CreateObject(((leave_her_uncle))).Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_AR_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 72 6c 6d 6f 6e 22 } //1 urlmon"
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 } //1 URLDownloadToFileA"
		$a_03_2 = {52 65 70 6c 61 63 65 28 22 7a 68 2e 73 65 74 61 64 70 75 2f 32 7a 68 2f 75 72 2e 41 42 56 6c 65 63 78 45 2f 2f 3a 70 74 74 68 22 2c 90 02 0f 43 68 72 28 31 31 32 29 20 26 20 43 68 72 28 31 30 34 29 20 26 20 43 68 72 28 31 31 32 29 29 90 00 } //1
		$a_01_3 = {55 52 4c 24 20 3d 20 22 68 74 74 70 3a 2f 2f 65 78 63 65 6c 76 62 61 2e 72 75 2f 75 70 64 61 74 65 73 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 61 64 64 69 6e 3d 50 61 72 73 65 72 } //1 URL$ = "http://excelvba.ru/updates/download.php?addin=Parser
		$a_01_4 = {28 22 74 6d 70 22 29 20 26 } //1 ("tmp") &
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_AR_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4c 4b 4f 4a 48 46 54 44 54 59 46 56 4b 44 53 46 46 56 22 2c 20 54 72 75 65 29 } //10 .CreateTextFile("C:\ProgramData\LKOJHFTDTYFVKDSFFV", True)
		$a_01_1 = {2e 45 78 65 63 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 52 65 2e 4a 6f 2e 54 61 67 } //10 .Exec "explorer.exe " & Re.Jo.Tag
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_3 = {46 48 44 79 68 6e 73 66 78 67 75 68 78 66 6e 68 67 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 56 65 72 65 72 79 22 29 } //1 FHDyhnsfxguhxfnhg.WriteLine ("Verery")
		$a_01_4 = {53 65 74 20 46 48 44 79 68 6e 73 66 78 67 75 68 78 66 6e 68 67 20 3d 20 52 65 74 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 52 65 2e 4a 6f 2e 54 61 67 2c 20 54 72 75 65 29 } //1 Set FHDyhnsfxguhxfnhg = Ret.CreateTextFile(Re.Jo.Tag, True)
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}