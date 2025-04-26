
rule TrojanDownloader_O97M_EncDoc_SNKQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SNKQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 77 52 37 4e 35 51 51 28 67 68 51 72 4c 59 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 53 74 72 69 6e 67 } //1 Public Function wR7N5QQ(ghQrLY As String) As String
		$a_01_1 = {53 65 74 20 61 39 7a 57 47 57 63 72 4d 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 56 42 53 63 72 69 70 74 2e 52 65 67 45 78 70 22 29 } //1 Set a9zWGWcrM = CreateObject("VBScript.RegExp")
		$a_01_2 = {49 77 44 55 35 76 50 53 42 20 3d 20 41 72 72 61 79 28 67 68 51 72 4c 59 29 } //1 IwDU5vPSB = Array(ghQrLY)
		$a_01_3 = {57 69 74 68 20 61 39 7a 57 47 57 63 72 4d } //1 With a9zWGWcrM
		$a_01_4 = {2e 50 61 74 74 65 72 6e 20 3d 20 22 6a 7c 51 7c 4c 7c 49 7c 46 7c 76 7c 44 7c 42 7c 54 7c 71 7c 77 7c 48 7c 7a 7c 5a 7c 4f 7c 58 7c 59 7c 50 7c 47 7c 4d 7c 4e 22 } //1 .Pattern = "j|Q|L|I|F|v|D|B|T|q|w|H|z|Z|O|X|Y|P|G|M|N"
		$a_01_5 = {2e 47 6c 6f 62 61 6c 20 3d 20 54 72 75 65 } //1 .Global = True
		$a_01_6 = {45 6e 64 20 57 69 74 68 } //1 End With
		$a_03_7 = {77 52 37 4e 35 51 51 20 3d 20 61 39 7a 57 47 57 63 72 4d 2e 52 65 70 6c 61 63 65 28 49 77 44 55 35 76 50 53 42 28 30 29 2c 20 22 22 29 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=8
 
}