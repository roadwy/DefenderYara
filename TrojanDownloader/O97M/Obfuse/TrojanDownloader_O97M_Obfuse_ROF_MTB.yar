
rule TrojanDownloader_O97M_Obfuse_ROF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ROF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 61 70 70 77 6f 72 64 2e 63 61 63 68 65 22 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_1 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1  = CreateObject("Wscript.Shell")
		$a_01_2 = {73 74 72 44 61 74 61 4f 75 74 20 3d 20 73 74 72 44 61 74 61 4f 75 74 20 2b 20 43 68 72 28 69 6e 74 58 4f 72 56 61 6c 75 65 31 20 58 6f 72 20 69 6e 74 58 4f 72 56 61 6c 75 65 32 29 } //1 strDataOut = strDataOut + Chr(intXOrValue1 Xor intXOrValue2)
		$a_03_3 = {6c 6f 6e 67 53 74 72 69 6e 67 20 3d 20 6c 6f 6e 67 53 74 72 69 6e 67 20 26 20 22 [0-5f] 3d 3d 22 } //1
		$a_01_4 = {20 3d 20 44 65 63 6f 64 65 36 34 28 6c 6f 6e 67 53 74 72 69 6e 67 29 } //1  = Decode64(longString)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}