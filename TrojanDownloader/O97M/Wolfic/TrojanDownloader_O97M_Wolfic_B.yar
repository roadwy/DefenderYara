
rule TrojanDownloader_O97M_Wolfic_B{
	meta:
		description = "TrojanDownloader:O97M/Wolfic.B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6c 69 61 73 20 22 43 72 65 61 74 65 50 72 6f 63 65 73 73 22 } //1 Alias "CreateProcess"
		$a_02_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-40] 2e 43 61 70 74 69 6f 6e 20 26 20 [0-40] 2e 43 61 70 74 69 6f 6e 29 } //1
		$a_02_2 = {22 68 74 74 70 73 3a 2f 2f [0-40] 2e 6c 6b 2f 64 2f [0-40] 62 61 63 6b 67 72 6f 75 6e 64 2e 70 6e 67 } //1
		$a_01_3 = {2e 53 74 61 74 75 73 20 3d 20 32 30 30 20 54 68 65 6e } //1 .Status = 200 Then
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}