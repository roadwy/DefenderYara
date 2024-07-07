
rule TrojanDownloader_Linux_Wopert_B{
	meta:
		description = "TrojanDownloader:Linux/Wopert.B,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 64 65 63 72 79 70 74 28 } //2 Function decrypt(
		$a_01_1 = {76 61 72 30 20 3d 20 64 65 63 72 79 70 74 28 } //2 var0 = decrypt(
		$a_01_2 = {56 61 72 20 3d 20 76 61 72 30 } //1 Var = var0
		$a_01_3 = {53 68 65 6c 6c 20 28 56 61 72 29 } //2 Shell (Var)
		$a_01_4 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_01_5 = {4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 66 69 72 73 74 2c 20 31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 } //2 Mid(strInput, first, 1) = Chr(Asc(Mid
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=8
 
}