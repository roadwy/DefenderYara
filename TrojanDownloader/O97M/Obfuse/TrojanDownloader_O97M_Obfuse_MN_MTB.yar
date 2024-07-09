
rule TrojanDownloader_O97M_Obfuse_MN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-0a] 28 22 20 61 57 20 61 53 63 20 61 72 69 20 61 70 74 20 61 22 20 26 20 22 20 61 2e 53 68 20 61 65 6c 20 61 6c 22 29 29 } //1
		$a_00_1 = {2e 43 61 70 74 69 6f 6e 20 3d 20 46 69 4e 65 72 74 79 28 22 52 75 20 61 6e 22 29 } //1 .Caption = FiNerty("Ru an")
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 2e 2e 5c 2e 2e 5c 2e 2e 5c 2e 2e 5c 2e 2e 22 } //1 Application.StartupPath & "\..\..\..\..\.."
		$a_03_3 = {4d 65 2e 4e 61 6d 65 20 26 20 [0-0a] 20 26 20 22 2e 74 78 74 74 78 74 74 78 74 2e 22 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}