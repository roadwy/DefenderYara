
rule TrojanDownloader_O97M_Powdow_BNN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BNN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 64 66 64 66 20 3d 20 72 64 61 75 2e 4f 70 65 6e 28 76 30 64 66 20 2b 20 22 5c 65 55 4f 4b 6d 2e 62 61 74 22 29 } //1 bdfdf = rdau.Open(v0df + "\eUOKm.bat")
		$a_01_1 = {68 6f 79 71 6f 20 3d 20 52 61 6e 67 65 28 22 42 31 30 35 22 29 2e 56 61 6c 75 65 20 2b 20 22 20 22 20 2b 20 52 61 6e 67 65 28 22 42 31 30 34 22 29 2e 56 61 6c 75 65 20 2b 20 52 61 6e 67 65 28 22 42 31 30 33 22 29 2e 56 61 6c 75 65 20 2b 20 22 20 2d 22 20 2b 20 72 65 76 28 52 61 6e 67 65 28 22 42 31 30 32 22 29 2e 56 61 6c 75 65 29 20 2b 20 72 65 76 28 52 61 6e 67 65 28 22 42 31 30 30 22 29 2e 56 61 6c 75 65 29 } //1 hoyqo = Range("B105").Value + " " + Range("B104").Value + Range("B103").Value + " -" + rev(Range("B102").Value) + rev(Range("B100").Value)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}