
rule TrojanDownloader_O97M_Powdow_AA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.AA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 22 20 2b 20 22 6e 6d 67 22 20 2b 20 22 6d 74 73 22 20 2b 20 22 3a 57 69 22 20 2b 20 22 6e 33 32 5f 22 20 2b 20 22 50 72 22 20 2b 20 22 6f 63 22 20 2b 20 22 65 73 73 22 29 } //1 = GetObject("wi" + "nmg" + "mts" + ":Wi" + "n32_" + "Pr" + "oc" + "ess")
		$a_03_1 = {2e 57 72 69 74 65 20 43 68 72 28 43 42 79 74 65 28 22 26 48 22 20 26 20 4d 69 64 28 [0-20] 2c 20 6c 70 2c 20 32 29 29 29 3a 20 4e 65 78 74 3a 20 45 6e 64 20 57 69 74 68 3a 20 6f 62 6a 46 69 6c 65 2e 43 6c 6f 73 65 } //1
		$a_01_2 = {4d 73 67 42 6f 78 20 22 54 68 65 20 64 22 20 2b 20 22 6f 63 75 6d 22 20 2b 20 22 65 6e 74 20 22 20 2b 20 22 69 73 20 70 72 6f 22 20 2b 20 22 74 65 63 74 65 64 22 20 2b 20 22 2c 20 79 6f 75 20 77 69 22 20 2b 20 22 6c 6c 20 6e 65 22 20 2b 20 22 65 64 20 74 6f 20 73 70 22 20 2b 20 22 65 63 69 22 20 2b 20 22 66 79 20 61 20 70 61 22 20 2b 20 22 73 73 77 6f 22 20 2b 20 22 72 64 20 74 6f 20 75 6e 22 20 2b 20 22 6c 6f 63 6b 2e 22 } //1 MsgBox "The d" + "ocum" + "ent " + "is pro" + "tected" + ", you wi" + "ll ne" + "ed to sp" + "eci" + "fy a pa" + "sswo" + "rd to un" + "lock."
		$a_01_3 = {45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 } //1 Environ("APPDATA")
		$a_01_4 = {2e 43 72 65 61 74 65 } //1 .Create
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}