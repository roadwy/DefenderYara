
rule HackTool_O97M_Pojeten_B_MTB{
	meta:
		description = "HackTool:O97M/Pojeten.B!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c } //1 CreateObject("WScript.Shell
		$a_00_1 = {5c 5c 45 78 63 65 6c 5c 5c 53 65 63 75 72 69 74 79 5c 5c 41 63 63 65 73 73 56 42 4f 4d } //1 \\Excel\\Security\\AccessVBOM
		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 } //1 CreateObject("Microsoft.XMLHTTP
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d } //1 CreateObject("ADODB.Stream
		$a_02_4 = {2e 57 72 69 74 65 [0-20] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //1
		$a_00_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 45 78 63 65 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //1 CreateObject("Excel.Application
		$a_00_6 = {2e 52 65 67 69 73 74 65 72 58 4c 4c 28 } //1 .RegisterXLL(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}