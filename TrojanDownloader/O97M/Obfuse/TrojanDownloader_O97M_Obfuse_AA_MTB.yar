
rule TrojanDownloader_O97M_Obfuse_AA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {57 69 63 6d 64 2e 43 72 65 61 74 65 46 6f 6c 64 65 72 20 22 43 3a 5c 70 69 63 31 5c 22 } //1 Wicmd.CreateFolder "C:\pic1\"
		$a_01_3 = {3d 20 22 43 3a 5c 70 69 63 31 5c 42 75 69 6c 64 31 36 2e 63 6d 64 22 } //1 = "C:\pic1\Build16.cmd"
		$a_03_4 = {22 73 74 61 72 74 20 63 3a 5c 70 69 63 31 5c 90 17 02 07 08 50 72 65 76 69 65 77 50 72 65 76 69 65 77 32 2e 65 78 65 22 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}