
rule TrojanDownloader_O97M_Powdow_BRTB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BRTB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 77 55 34 61 63 7a 38 43 44 28 64 4d 69 6d 70 20 41 73 20 53 74 72 69 6e 67 2c 20 64 4d 69 6d 70 32 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 53 74 72 69 6e 67 } //1 Public Function wU4acz8CD(dMimp As String, dMimp2 As String) As String
		$a_01_1 = {53 65 74 20 75 71 76 54 4d 59 35 51 41 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 64 4d 69 6d 70 32 29 } //1 Set uqvTMY5QA = CreateObject(dMimp2)
		$a_01_2 = {77 55 34 61 63 7a 38 43 44 20 3d 20 75 71 76 54 4d 59 35 51 41 2e 52 65 70 6c 61 63 65 28 6e 6e 4d 68 76 28 30 29 2c 20 22 22 29 } //1 wU4acz8CD = uqvTMY5QA.Replace(nnMhv(0), "")
		$a_01_3 = {77 55 34 61 63 7a 38 43 44 20 3d 20 77 55 34 61 63 7a 38 43 44 20 2b 20 43 68 72 28 41 73 63 28 4d 69 64 28 6e 6e 4d 68 76 2c 20 4c 65 6e 28 6e 6e 4d 68 76 29 20 2d 20 69 20 2b 20 31 2c 20 31 29 29 20 2d 20 32 29 } //1 wU4acz8CD = wU4acz8CD + Chr(Asc(Mid(nnMhv, Len(nnMhv) - i + 1, 1)) - 2)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}