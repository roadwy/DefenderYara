
rule TrojanDropper_Win32_Alureon_Z{
	meta:
		description = "TrojanDropper:Win32/Alureon.Z,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 45 78 65 63 44 6f 73 2e 64 6c 6c } //01 00  \ExecDos.dll
		$a_01_1 = {5c 37 7a 61 2e 65 78 65 22 20 78 20 22 } //01 00  \7za.exe" x "
		$a_01_2 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  Set fso = CreateObject("Scripting.FileSystemObject")
		$a_01_3 = {53 65 74 20 77 73 63 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set wsc = CreateObject("WScript.Shell")
		$a_01_4 = {53 65 74 20 62 61 74 63 68 20 3d 20 66 73 6f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 } //01 00  Set batch = fso.CreateTextFile(
		$a_01_5 = {62 61 74 63 68 2e 57 72 69 74 65 4c 69 6e 65 20 22 63 6d 64 20 2f 43 20 20 70 69 6e 67 20 2d 6e 20 31 20 20 6c 6f 63 61 6c 68 6f 73 74 20 3e 20 6e 75 6c 20 26 20 64 65 6c } //00 00  batch.WriteLine "cmd /C  ping -n 1  localhost > nul & del
	condition:
		any of ($a_*)
 
}