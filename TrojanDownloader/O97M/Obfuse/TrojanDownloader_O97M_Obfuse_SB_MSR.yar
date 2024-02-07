
rule TrojanDownloader_O97M_Obfuse_SB_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SB!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 77 6e 6c 6f 61 64 } //01 00  Download
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //03 00  ShellExecute
		$a_03_2 = {68 74 74 70 73 3a 2f 2f 64 61 6e 67 65 72 6f 75 73 6c 79 2e 90 02 15 73 76 63 2e 64 6c 6c 90 00 } //03 00 
		$a_03_3 = {68 74 74 70 3a 2f 2f 67 72 61 72 73 2e 63 6f 6d 2f 90 02 06 2e 65 78 65 90 00 } //03 00 
		$a_03_4 = {68 74 74 70 3a 2f 2f 74 61 6d 62 6f 65 2e 6e 65 74 2f 90 02 06 2e 65 78 65 90 00 } //03 00 
		$a_03_5 = {68 74 74 70 3a 2f 2f 72 65 74 6f 68 2e 63 6f 6d 2f 90 02 06 2e 65 78 65 90 00 } //03 00 
		$a_03_6 = {68 74 74 70 3a 2f 2f 6b 77 61 74 6f 76 2e 63 6f 6d 2f 90 02 06 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_SB_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SB!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 68 65 65 74 90 02 01 2e 4f 4c 45 4f 62 6a 65 63 74 73 28 22 4f 62 6a 65 63 74 90 02 02 22 29 2e 43 6f 70 79 90 00 } //01 00 
		$a_01_1 = {65 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 41 50 50 44 41 54 41 25 22 29 } //01 00  expandEnvironmentStrings("%APPDATA%")
		$a_01_2 = {4d 6b 44 69 72 20 22 43 3a 22 20 2b 20 22 5c 4b 42 34 22 20 2b 20 22 } //01 00  MkDir "C:" + "\KB4" + "
		$a_01_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  CreateObject("Wscript.Shell")
		$a_01_4 = {53 68 65 6c 6c 2e 52 75 6e 20 22 53 63 68 54 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 53 43 } //01 00  Shell.Run "SchTasks /Create /SC
		$a_01_5 = {43 6f 70 79 46 69 6c 65 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 4b 42 34 22 20 2b } //00 00  CopyFile Environ("Temp") & "\KB4" +
	condition:
		any of ($a_*)
 
}