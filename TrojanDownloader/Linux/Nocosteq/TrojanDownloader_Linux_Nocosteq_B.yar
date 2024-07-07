
rule TrojanDownloader_Linux_Nocosteq_B{
	meta:
		description = "TrojanDownloader:Linux/Nocosteq.B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 53 47 45 54 53 41 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //1 Set SGETSA = CreateObject("Microsoft.XMLHTTP")
		$a_01_1 = {53 65 74 20 53 50 4f 53 54 53 41 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //1 Set SPOSTSA = CreateObject("ADODB.Stream")
		$a_01_2 = {43 61 6c 6c 20 53 68 65 6c 6c 28 46 75 6c 6c 53 61 76 65 50 61 74 68 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1 Call Shell(FullSavePath, vbNormalFocus)
		$a_01_3 = {4d 73 67 42 6f 78 20 22 45 73 74 65 20 64 6f 63 75 6d 65 6e 74 6f 20 6e 6f 20 65 73 20 63 6f 6d 70 61 74 69 62 6c 65 20 63 6f 6e 20 65 73 74 65 20 65 71 75 69 70 6f 2e } //1 MsgBox "Este documento no es compatible con este equipo.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}