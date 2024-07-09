
rule TrojanDropper_O97M_Obfuse_ZQ_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.ZQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_00_1 = {45 6e 76 69 72 6f 6e 28 22 4c 4f 43 41 4c 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 42 61 63 6b 75 70 22 } //1 Environ("LOCALAPPDATA") & "\MicrosoftBackup"
		$a_00_2 = {28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4e 61 6d 65 73 70 61 63 65 28 70 61 74 68 31 29 } //1 ("Shell.Application").Namespace(path1)
		$a_00_3 = {22 5c 4d 69 63 72 6f 73 6f 66 74 42 61 63 6b 75 70 22 20 26 20 22 5c 22 20 26 20 6d 79 6e 61 6d 65 20 26 20 22 2e 65 78 65 22 } //1 "\MicrosoftBackup" & "\" & myname & ".exe"
		$a_00_4 = {41 70 70 64 61 74 61 41 64 64 72 65 73 73 20 26 20 22 5c 6e 63 2e 65 78 65 22 } //1 AppdataAddress & "\nc.exe"
		$a_03_5 = {2e 52 75 6e 20 43 68 72 28 [0-03] 29 20 26 20 70 61 74 68 31 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}