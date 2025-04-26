
rule TrojanDropper_Linux_Avosim_B{
	meta:
		description = "TrojanDropper:Linux/Avosim.B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 20 2f 63 20 65 63 68 6f 20 22 20 26 20 43 68 72 28 } //1 .Run "cmd.exe  /c echo " & Chr(
		$a_00_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 5b 49 4f 2e 46 69 6c 65 5d 3a 3a 57 72 69 74 65 41 6c 6c 42 79 74 65 73 28 } //1 powershell.exe [IO.File]::WriteAllBytes(
		$a_00_2 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 46 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 33 20 2f 74 6e } //1 schtasks /create /F /sc minute /mo 3 /tn
		$a_00_3 = {2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 20 2f 63 20 65 63 68 6f 20 22 20 26 20 22 53 65 74 } //1 .Run "cmd.exe  /c echo " & "Set
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}