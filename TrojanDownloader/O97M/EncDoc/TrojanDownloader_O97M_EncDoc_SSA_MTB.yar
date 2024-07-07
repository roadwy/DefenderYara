
rule TrojanDownloader_O97M_EncDoc_SSA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 68 6d 59 4a 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6e 31 29 } //1 Set hmYJ = CreateObject(n1)
		$a_01_1 = {68 6d 59 4a 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 43 65 6c 6c 73 28 37 2c 20 31 29 2c 20 41 32 2c 20 22 22 2c 20 22 22 2c 20 30 } //1 hmYJ.ShellExecute "P" + Cells(7, 1), A2, "", "", 0
		$a_01_2 = {72 65 76 20 3d 20 72 65 76 20 26 20 4d 69 64 28 4d 41 4b 47 61 63 56 2c 20 70 2c 20 31 29 } //1 rev = rev & Mid(MAKGacV, p, 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}