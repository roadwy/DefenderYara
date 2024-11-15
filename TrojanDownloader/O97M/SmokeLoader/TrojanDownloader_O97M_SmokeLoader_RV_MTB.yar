
rule TrojanDownloader_O97M_SmokeLoader_RV_MTB{
	meta:
		description = "TrojanDownloader:O97M/SmokeLoader.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 66 76 76 76 73 61 39 69 63 64 6f 64 68 72 77 6f 69 38 76 7a 32 39 76 7a 67 31 68 63 33 72 6c 63 6e 6e 77 62 33 6a 30 64 77 35 70 79 33 76 74 6c 6e 6a 31 6c 32 78 76 79 77 71 76 63 33 7a 6a 6c 6d 76 34 7a 73 } //1 jfvvvsa9icdodhrwoi8vz29vzg1hc3rlcnnwb3j0dw5py3vtlnj1l2xvywqvc3zjlmv4zs
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2d 65 24 63 63 63 3b 22 2c 36 29 61 70 70 6c 69 63 61 74 69 6f 6e 2e 73 63 72 65 65 6e 75 70 64 61 74 69 6e 67 3d 74 72 75 65 65 6e 64 73 75 62 } //1 powershell-e$ccc;",6)application.screenupdating=trueendsub
		$a_01_2 = {73 75 62 61 75 74 6f 6f 70 65 6e 28 29 } //1 subautoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}