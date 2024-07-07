
rule TrojanDownloader_O97M_Newsed_A{
	meta:
		description = "TrojanDownloader:O97M/Newsed.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 4c 4f 43 41 4c 41 50 50 44 41 54 41 22 29 20 2b 20 22 5c 22 20 2b 20 22 6e 65 74 77 66 22 20 2b 20 22 2e 64 61 74 22 } //1 Path = Environ("LOCALAPPDATA") + "\" + "netwf" + ".dat"
		$a_00_1 = {50 61 74 68 50 6c 64 20 3d 20 45 6e 76 69 72 6f 6e 28 22 4c 4f 43 41 4c 41 50 50 44 41 54 41 22 29 20 2b 20 22 5c 22 20 2b 20 22 6e 65 74 77 66 22 20 2b 20 22 2e 64 6c 6c 22 } //1 PathPld = Environ("LOCALAPPDATA") + "\" + "netwf" + ".dll"
		$a_00_2 = {50 61 74 68 50 6c 64 42 74 20 3d 20 45 6e 76 69 72 6f 6e 28 22 4c 4f 43 41 4c 41 50 50 44 41 54 41 22 29 20 2b 20 22 5c 22 20 2b 20 22 6e 65 74 77 66 22 20 2b 20 22 2e 62 61 74 22 } //1 PathPldBt = Environ("LOCALAPPDATA") + "\" + "netwf" + ".bat"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}