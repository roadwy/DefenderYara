
rule TrojanDownloader_O97M_Donoff_SSE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SSE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 50 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 44 52 4d 36 39 41 37 32 46 39 38 28 22 20 26 20 69 20 26 20 22 29 2e 65 78 65 22 } //1 exePath = Environ("TEMP") & "\DRM69A72F98(" & i & ").exe"
		$a_03_1 = {78 68 72 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 79 32 30 32 35 75 2e 7a 79 6e 73 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 73 2f [0-0a] 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}