
rule TrojanDownloader_O97M_Obfuse_ASM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ASM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 6a 64 6a 6b 61 73 66 20 3d 20 22 [0-05] 6a 64 73 6c 61 64 6b 66 22 } //1
		$a_01_1 = {66 6a 64 6a 6b 61 73 66 20 3d 20 4c 65 66 74 28 66 6a 64 6a 6b 61 73 66 2c 20 35 29 } //1 fjdjkasf = Left(fjdjkasf, 5)
		$a_03_2 = {64 6a 66 65 69 68 66 69 64 6b 61 73 6c 6a 66 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 64 66 67 64 66 6a 69 65 6a 66 6a 64 73 68 61 6a 2c 20 [0-1f] 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 30 } //1
		$a_01_3 = {53 65 74 20 64 6a 66 65 69 68 66 69 64 6b 61 73 6c 6a 66 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set djfeihfidkasljf = CreateObject("Shell.Application")
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}