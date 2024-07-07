
rule TrojanDropper_Linux_Donoff_A{
	meta:
		description = "TrojanDropper:Linux/Donoff.A,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 } //1 ActiveDocument.Range.Text
		$a_01_1 = {4f 70 65 6e 20 74 6d 70 64 20 46 6f 72 20 42 69 6e 61 72 79 20 4c 6f 63 6b 20 57 72 69 74 65 20 41 73 } //1 Open tmpd For Binary Lock Write As
		$a_01_2 = {57 68 69 6c 65 20 28 62 57 72 69 74 74 65 6e 20 3c 20 4c 65 6e 28 6c 70 54 65 78 74 44 61 74 61 29 29 } //1 While (bWritten < Len(lpTextData))
		$a_01_3 = {53 79 6d 62 6f 6c 20 3d 20 4d 69 64 28 6c 70 54 65 78 74 44 61 74 61 2c 20 62 57 72 69 74 74 65 6e 2c } //1 Symbol = Mid(lpTextData, bWritten,
		$a_03_4 = {50 75 74 20 90 02 10 20 43 42 79 74 65 28 53 79 6d 62 6f 6c 29 90 00 } //1
		$a_01_5 = {62 57 72 69 74 74 65 6e 20 3d 20 62 57 72 69 74 74 65 6e 20 2b 20 } //1 bWritten = bWritten + 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}