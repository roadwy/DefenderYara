
rule TrojanDownloader_O97M_Emotet_BEM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.BEM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 43 65 6c 6c 73 28 36 35 2c 20 31 29 2c 20 22 65 72 6e 22 2c 20 22 22 29 } //1 Replace(Cells(65, 1), "ern", "")
		$a_01_1 = {4f 70 65 6e 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 76 6b 77 65 72 2e 62 61 74 22 } //1 Open "c:\programdata\vkwer.bat"
		$a_01_2 = {73 74 72 4d 65 73 73 61 67 65 20 3d 20 22 20 22 20 26 20 2e 4e 61 6d 65 20 26 20 22 20 2c 20 22 20 26 20 76 62 43 72 20 26 20 5f } //1 strMessage = " " & .Name & " , " & vbCr & _
		$a_01_3 = {4d 73 67 42 6f 78 20 45 72 72 2e 44 65 73 63 72 69 70 74 69 6f 6e 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 22 20 26 20 22 20 26 20 45 72 72 2e 4e 75 6d 62 65 72 } //1 MsgBox Err.Description, vbCritical, " & " & Err.Number
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}