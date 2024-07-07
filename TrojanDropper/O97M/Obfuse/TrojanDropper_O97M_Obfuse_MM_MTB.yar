
rule TrojanDropper_O97M_Obfuse_MM_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.MM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {6e 74 67 73 29 20 26 20 22 4c 6f 63 61 6c 5c 54 65 6d 70 22 } //1 ntgs) & "Local\Temp"
		$a_00_1 = {41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 } //1 AttachedTemplate.Path & "\W0rd.dll"
		$a_00_2 = {33 32 2e 65 78 65 } //1 32.exe
		$a_00_3 = {22 5c 57 30 72 64 2e 64 6c 6c 2c 53 74 61 72 74 22 } //1 "\W0rd.dll,Start"
		$a_00_4 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 .ShellExecute
		$a_00_5 = {52 6f 6f 74 50 61 74 68 20 26 20 22 5c 79 61 2e 77 61 76 22 } //1 RootPath & "\ya.wav"
		$a_00_6 = {73 66 20 26 20 22 5c 79 61 2e 77 61 76 22 } //1 sf & "\ya.wav"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}