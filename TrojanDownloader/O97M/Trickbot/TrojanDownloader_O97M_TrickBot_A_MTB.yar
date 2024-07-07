
rule TrojanDownloader_O97M_TrickBot_A_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.A!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 56 42 41 37 20 54 68 65 6e } //1 #If VBA7 Then
		$a_01_1 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 53 65 74 46 6f 63 75 73 20 4c 69 62 20 22 75 73 65 72 33 32 22 20 28 42 79 56 61 6c 20 68 57 6e 64 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 4c 6f 6e 67 50 74 72 } //1 Public Declare PtrSafe Function SetFocus Lib "user32" (ByVal hWnd As Long) As LongPtr
		$a_03_2 = {43 75 72 44 65 70 20 3d 20 43 75 72 44 65 70 20 2b 20 90 02 16 20 2a 20 43 65 69 6c 28 90 02 18 20 2b 20 90 02 18 20 2a 20 47 65 74 42 61 63 6b 29 90 00 } //1
		$a_03_3 = {76 69 73 69 74 63 6d 64 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 73 74 61 72 74 20 63 3a 5c 47 72 6f 75 70 4c 6f 67 73 5c 90 02 10 2e 65 78 65 22 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}