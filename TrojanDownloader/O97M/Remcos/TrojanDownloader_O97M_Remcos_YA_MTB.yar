
rule TrojanDownloader_O97M_Remcos_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Remcos.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 73 70 6c 2e 43 72 65 61 74 65 28 4e 78 61 79 70 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 6d 68 30 66 35 29 } //1 Pspl.Create(Nxayp, Null, Null, mh0f5)
		$a_01_1 = {53 65 74 20 50 73 70 6c 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 41 31 29 } //1 Set Pspl = GetObject(A1)
		$a_01_2 = {4e 78 61 79 70 20 3d 20 41 32 20 2b 20 22 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 24 66 64 34 65 72 37 66 30 3d } //1 Nxayp = A2 + " -WindowStyle Hidden $fd4er7f0=
		$a_01_3 = {24 6a 6d 20 2d 6a 6f 69 6e 20 27 27 7c 49 60 45 60 58 } //1 $jm -join ''|I`E`X
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}