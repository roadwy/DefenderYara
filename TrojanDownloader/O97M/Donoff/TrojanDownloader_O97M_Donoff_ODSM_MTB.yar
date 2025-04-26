
rule TrojanDownloader_O97M_Donoff_ODSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.ODSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 63 61 72 69 6e 74 65 72 66 61 63 65 5f 6e 61 6d 65 28 62 79 76 61 6c 6e 61 6d 65 61 73 73 74 72 69 6e 67 29 } //1 publicfunctioncarinterface_name(byvalnameasstring)
		$a_01_1 = {6f 70 65 6e 77 6f 72 6c 64 3d 6f 6e 65 64 61 79 31 2e 74 61 67 } //1 openworld=oneday1.tag
		$a_01_2 = {73 6f 63 69 61 6c 77 6f 72 6c 64 3d 6f 6e 65 64 61 79 31 2e 6f 70 65 6e 61 6e 64 73 68 75 74 2e 74 61 67 2b 6f 6e 65 64 61 79 31 2e 62 75 74 74 6f 6e 2e 74 61 67 } //1 socialworld=oneday1.openandshut.tag+oneday1.button.tag
		$a_01_3 = {73 6f 66 74 63 6f 72 6e 65 72 3d 6f 70 65 6e 77 6f 72 6c 64 2b 22 22 2b 73 6f 63 69 61 6c 77 6f 72 6c 64 } //1 softcorner=openworld+""+socialworld
		$a_01_4 = {63 61 72 69 6e 74 65 72 66 61 63 65 5f 6e 61 6d 65 28 73 6f 66 74 63 6f 72 6e 65 72 29 } //1 carinterface_name(softcorner)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}