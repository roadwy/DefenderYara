
rule TrojanDownloader_O97M_Obfuse_IM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2e 6a 73 22 } //1 .js"
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 77 69 6e 64 69 72 22 29 20 2b 20 22 5c 54 65 6d 70 22 } //1 = Environ("windir") + "\Temp"
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 30 29 } //1 .Controls(0)
		$a_03_3 = {4f 70 65 6e 20 [0-15] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } //1
		$a_01_4 = {20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1  CreateObject("Scripting.FileSystemObject")
		$a_03_5 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-15] 2c 20 54 72 75 65 29 } //1
		$a_01_6 = {2e 43 61 70 74 69 6f 6e } //1 .Caption
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}