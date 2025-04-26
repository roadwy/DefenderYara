
rule TrojanDropper_O97M_Drixed_B{
	meta:
		description = "TrojanDropper:O97M/Drixed.B,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 .CreateObject("WScript.Shell")
		$a_00_1 = {2c 20 22 25 74 65 6d 70 25 22 29 } //1 , "%temp%")
		$a_00_2 = {26 20 22 5c 63 68 61 6f 74 69 63 2e 65 78 65 } //1 & "\chaotic.exe
		$a_00_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_02_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 69 67 68 74 28 22 [0-10] 22 2c 20 [0-02] 29 20 2b 20 4c 65 66 74 28 22 [0-10] 22 2c 20 [0-02] 29 29 } //1
		$a_00_5 = {43 42 79 74 65 28 22 26 22 20 2b 20 43 68 72 28 } //1 CByte("&" + Chr(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}