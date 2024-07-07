
rule TrojanDownloader_O97M_Obfuse_FY{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FY,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e } //1 #If Win64 Then
		$a_01_1 = {44 69 6d 20 46 6b 6a 68 64 6b 73 6a 6a 67 6a 6b 73 76 20 41 73 20 53 74 72 69 6e 67 } //1 Dim Fkjhdksjjgjksv As String
		$a_01_2 = {43 61 6c 6c 20 73 67 73 64 6b 6a 61 62 6a 6b 61 6a 68 61 62 76 6a 6b 68 61 62 76 6c 6b 61 64 6e 6b 6a 61 6e 76 6b 6a 61 62 76 } //1 Call sgsdkjabjkajhabvjkhabvlkadnkjanvkjabv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}