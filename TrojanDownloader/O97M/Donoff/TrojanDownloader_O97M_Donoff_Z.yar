
rule TrojanDownloader_O97M_Donoff_Z{
	meta:
		description = "TrojanDownloader:O97M/Donoff.Z,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 28 4e 29 20 26 20 22 5c 22 } //1 = Environ(N) & "\"
		$a_03_1 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 90 05 20 06 61 2d 7a 30 2d 39 2c 20 90 05 20 06 61 2d 7a 30 2d 39 2c 20 32 29 29 29 } //1
		$a_01_2 = {42 20 3d 20 53 68 65 6c 6c 28 44 2c } //1 B = Shell(D,
		$a_01_3 = {41 72 72 61 79 28 22 61 74 61 44 70 70 41 22 2c 20 22 50 4d 45 54 22 29 } //1 Array("ataDppA", "PMET")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}