
rule TrojanDownloader_Linux_Ledod_P{
	meta:
		description = "TrojanDownloader:Linux/Ledod.P,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 20 56 61 6c 28 22 26 48 22 20 26 20 28 4d 69 64 24 28 [0-0f] 2c 20 28 32 20 2a 20 73 6e 69 70 70 65 74 44 59 79 44 71 29 20 2d 20 31 2c 20 32 29 29 29 } //1
		$a_03_1 = {3d 20 41 73 63 28 4d 69 64 24 28 [0-0f] 2c 20 28 28 [0-0f] 20 4d 6f 64 20 4c 65 6e 28 [0-0f] 29 29 20 2b 20 31 29 2c 20 31 29 29 } //1
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 } //1 = Environ("TEMP")
		$a_01_3 = {3d 20 22 53 68 22 20 26 20 22 65 22 20 26 20 43 68 72 28 31 30 38 29 } //1 = "Sh" & "e" & Chr(108)
		$a_01_4 = {26 20 43 68 72 28 31 30 38 29 20 26 20 22 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //1 & Chr(108) & ".Application
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}