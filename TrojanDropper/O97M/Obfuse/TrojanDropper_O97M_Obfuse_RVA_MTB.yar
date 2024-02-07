
rule TrojanDropper_O97M_Obfuse_RVA_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  fso = CreateObject("Scripting.FileSystemObject")
		$a_01_1 = {6f 31 2e 52 75 6e 20 22 43 3a 5c 77 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 73 73 67 2e 65 78 65 22 } //01 00  o1.Run "C:\windows\Temp\ssg.exe"
		$a_01_2 = {53 65 74 20 6f 31 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set o1 = CreateObject("Wscript.Shell")
		$a_01_3 = {61 69 28 69 29 20 3d 20 22 26 48 22 20 26 20 61 73 49 6e 70 28 69 29 } //01 00  ai(i) = "&H" & asInp(i)
		$a_01_4 = {61 73 49 6e 70 20 3d 20 53 70 6c 69 74 28 22 34 64 20 35 61 20 39 30 20 30 } //01 00  asInp = Split("4d 5a 90 0
		$a_01_5 = {66 73 6f 2e 44 65 6c 65 74 65 46 69 6c 65 20 28 73 46 69 6c 65 29 } //01 00  fso.DeleteFile (sFile)
		$a_01_6 = {4f 70 65 6e 20 73 46 69 6c 65 20 46 6f 72 20 42 69 6e 61 72 79 20 4c 6f 63 6b 20 52 65 61 64 20 57 72 69 74 65 20 41 73 20 23 6e 46 69 6c 65 4e 75 6d } //00 00  Open sFile For Binary Lock Read Write As #nFileNum
	condition:
		any of ($a_*)
 
}