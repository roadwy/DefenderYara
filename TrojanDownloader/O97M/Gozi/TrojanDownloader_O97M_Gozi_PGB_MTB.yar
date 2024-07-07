
rule TrojanDownloader_O97M_Gozi_PGB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.PGB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 68 61 31 22 } //1 = Environ$("USERPROFILE") + "\ha1"
		$a_00_1 = {47 47 2e 63 72 65 61 74 65 20 53 52 34 20 2b 20 22 20 22 20 2b 20 53 54 50 20 2b 20 22 2e 74 78 74 } //1 GG.create SR4 + " " + STP + ".txt
		$a_00_2 = {47 47 2e 63 72 65 61 74 65 20 53 52 33 20 2b 20 22 20 22 20 2b 20 53 54 50 20 2b 20 22 2e 70 64 66 } //1 GG.create SR3 + " " + STP + ".pdf
		$a_00_3 = {52 65 73 75 6c 74 32 3a 20 53 6c 65 65 70 20 36 30 30 30 } //1 Result2: Sleep 6000
		$a_00_4 = {53 65 74 20 47 47 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 53 52 31 29 } //1 Set GG = CreateObject(SR1)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}