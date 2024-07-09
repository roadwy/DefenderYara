
rule TrojanDownloader_O97M_Obfuse_IA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 [0-10] 28 [0-16] 2c 20 22 76 65 72 69 6e 73 74 65 72 65 2e 78 6c 73 22 2c 20 30 29 } //1
		$a_01_1 = {2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 76 69 65 77 20 74 68 69 73 22 29 20 54 68 65 6e } //1 .Range.Text, "view this") Then
		$a_03_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-07] 2e 54 61 67 29 } //1
		$a_01_3 = {28 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 29 } //1 (Environ("TEMP"))
		$a_01_4 = {77 6f 72 64 73 54 6f 52 65 6d 6f 76 65 28 } //1 wordsToRemove(
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}