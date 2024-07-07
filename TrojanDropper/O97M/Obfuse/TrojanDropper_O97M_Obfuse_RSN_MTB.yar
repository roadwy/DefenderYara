
rule TrojanDropper_O97M_Obfuse_RSN_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.RSN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_03_1 = {6f 62 6a 53 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 54 45 4d 50 25 22 29 20 26 20 22 5c 63 79 6d 5f 90 02 13 2e 90 17 02 03 03 62 61 74 77 73 66 90 00 } //1
		$a_01_2 = {44 4d 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 74 6d 70 22 29 } //1 DM.createElement("tmp")
		$a_01_3 = {77 72 69 74 65 42 79 74 65 73 20 4e 61 6d 65 64 2c 20 64 65 63 6f 64 65 42 61 73 65 36 34 28 42 61 73 65 64 29 } //1 writeBytes Named, decodeBase64(Based)
		$a_01_4 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}