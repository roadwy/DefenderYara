
rule TrojanDownloader_Linux_Wopert_A{
	meta:
		description = "TrojanDownloader:Linux/Wopert.A,SIGNATURE_TYPE_MACROHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 65 63 72 79 70 74 28 44 65 63 6f 64 65 36 34 28 22 } //3 decrypt(Decode64("
		$a_01_1 = {28 28 28 55 42 6f 75 6e 64 28 62 49 6e 29 20 2b 20 31 29 20 5c 20 34 29 20 2a 20 33 29 20 2d 20 31 29 } //8 (((UBound(bIn) + 1) \ 4) * 3) - 1)
		$a_01_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 } //2 = ActiveDocument.BuiltInDocumentProperties(
		$a_01_3 = {4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 66 69 72 73 74 2c 20 31 29 20 3d 20 43 68 72 28 } //2 Mid(strInput, first, 1) = Chr(
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*8+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=15
 
}