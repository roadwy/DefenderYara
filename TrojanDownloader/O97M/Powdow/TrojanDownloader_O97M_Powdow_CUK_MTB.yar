
rule TrojanDownloader_O97M_Powdow_CUK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.CUK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 66 66 6b 6b 6a 74 65 73 76 64 6c 62 6f 6f 65 7a 6d 75 7a 6f 75 6f 74 66 70 20 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 61 6e 67 65 28 22 41 34 22 29 2e 56 61 6c 75 65 29 } //1 Set ffkkjtesvdlbooezmuzouotfp  = CreateObject(Range("A4").Value)
		$a_01_1 = {44 69 6d 20 6b 6d 6f 6a 72 72 6b 76 69 7a 66 69 71 75 77 67 73 72 71 61 77 72 69 76 6e } //1 Dim kmojrrkvizfiquwgsrqawrivn
		$a_01_2 = {6e 66 69 67 75 76 66 77 76 75 68 6c 65 79 6b 6c 73 73 74 78 65 67 66 74 62 20 3d 20 52 61 6e 67 65 28 22 41 33 22 29 2e 56 61 6c 75 65 } //1 nfiguvfwvuhleyklsstxegftb = Range("A3").Value
		$a_01_3 = {6b 6d 6f 6a 72 72 6b 76 69 7a 66 69 71 75 77 67 73 72 71 61 77 72 69 76 6e 20 3d 20 66 66 6b 6b 6a 74 65 73 76 64 6c 62 6f 6f 65 7a 6d 75 7a 6f 75 6f 74 66 70 2e 43 72 65 61 74 65 28 6e 66 69 67 75 76 66 77 76 75 68 6c 65 79 6b 6c 73 73 74 78 65 67 66 74 62 29 } //1 kmojrrkvizfiquwgsrqawrivn = ffkkjtesvdlbooezmuzouotfp.Create(nfiguvfwvuhleyklsstxegftb)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}