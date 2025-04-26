
rule TrojanDropper_Win16_Powdow_SG_MSR{
	meta:
		description = "TrojanDropper:Win16/Powdow.SG!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {49 66 20 4f 42 2e 46 69 6c 65 45 78 69 73 74 73 28 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6e 76 69 64 69 61 78 2e 65 78 65 22 29 20 3d 20 54 72 75 65 20 54 68 65 6e } //1 If OB.FileExists(Environ("temp") & "\nvidiax.exe") = True Then
		$a_00_1 = {4f 42 2e 44 65 6c 65 74 65 46 69 6c 65 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6e 76 69 64 69 61 78 2e 65 78 65 } //1 OB.DeleteFile Environ("temp") & "\nvidiax.exe
		$a_00_2 = {53 58 20 3d 20 53 58 20 26 20 57 6f 72 6b 73 68 65 65 74 73 28 22 46 69 6e 61 6c 20 4f 66 66 65 72 22 29 2e 52 61 6e 67 65 28 22 62 73 22 20 26 20 69 29 2e 56 61 6c 75 65 } //1 SX = SX & Worksheets("Final Offer").Range("bs" & i).Value
		$a_00_3 = {53 58 20 3d 20 54 72 69 6d 28 53 74 72 52 65 76 65 72 73 65 28 53 58 29 29 } //1 SX = Trim(StrReverse(SX))
		$a_00_4 = {6f 62 6a 4e 6f 64 65 2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 } //1 objNode.DataType = "bin.base64
		$a_00_5 = {56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 VBA.CreateObject("WScript.Shell")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}