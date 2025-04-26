
rule Tool_O97M_CbrSecByBssPoc{
	meta:
		description = "Tool:O97M/CbrSecByBssPoc,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {3d 20 28 28 62 79 49 6e 28 69 29 20 2b 20 4e 6f 74 20 62 45 6e 63 4f 72 44 65 63 29 20 58 6f 72 20 62 79 4b 65 79 28 6c 29 29 20 2d 20 62 45 6e 63 4f 72 44 65 63 } //1 = ((byIn(i) + Not bEncOrDec) Xor byKey(l)) - bEncOrDec
		$a_00_1 = {49 66 20 62 45 6e 63 4f 72 44 65 63 20 54 68 65 6e 20 58 6f 72 43 20 3d 20 22 78 78 78 22 20 26 20 58 6f 72 43 } //1 If bEncOrDec Then XorC = "xxx" & XorC
		$a_00_2 = {50 75 74 20 23 31 2c 20 6c 57 72 69 74 65 50 6f 73 2c 20 22 43 79 62 65 72 53 65 63 75 72 69 74 79 48 61 6d 62 75 72 67 22 } //2 Put #1, lWritePos, "CyberSecurityHamburg"
		$a_00_3 = {3d 20 58 6f 72 43 28 73 74 72 46 69 6e 61 6c 2c 20 22 43 79 62 65 72 53 65 63 75 72 69 74 79 42 79 42 53 53 22 29 } //2 = XorC(strFinal, "CyberSecurityByBSS")
		$a_00_4 = {4d 73 67 42 6f 78 20 22 52 61 6e 73 6f 6d 77 61 72 65 44 65 74 65 63 74 69 6f 6e 54 65 73 74 42 79 42 53 53 22 } //2 MsgBox "RansomwareDetectionTestByBSS"
		$a_00_5 = {45 6c 73 65 49 66 20 49 6e 53 74 72 28 6f 62 6a 46 69 6c 65 2e 4e 61 6d 65 2c 20 22 2e 22 29 20 41 6e 64 20 4e 6f 74 20 49 6e 53 74 72 28 6f 62 6a 46 69 6c 65 2e 4e 61 6d 65 2c 20 22 2e 78 6c 73 6d 22 29 20 54 68 65 6e } //1 ElseIf InStr(objFile.Name, ".") And Not InStr(objFile.Name, ".xlsm") Then
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1) >=3
 
}