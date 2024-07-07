
rule TrojanDropper_O97M_Obfuse_NZ_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.NZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2b 20 22 2e 64 22 20 2b 20 22 6c 6c 22 } //1 + ".d" + "ll"
		$a_03_1 = {55 73 65 72 46 6f 72 6d 90 01 01 2e 54 65 78 74 42 6f 78 90 01 01 2e 54 61 67 20 90 01 01 20 22 5c 90 02 20 22 20 2b 20 22 2e 78 6c 73 78 22 90 00 } //1
		$a_01_2 = {22 2e 7a 69 70 22 } //1 ".zip"
		$a_01_3 = {2e 4e 61 6d 65 73 70 61 63 65 28 5a 69 70 46 6f 6c 64 65 72 29 2e 43 6f 70 79 48 65 72 65 20 6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 5a 69 70 4e 61 6d 65 29 2e 69 74 65 6d 73 2e 49 74 65 6d 28 22 78 6c 5c 65 6d 62 65 64 64 69 6e 67 73 5c 6f 6c 65 4f 62 6a 65 63 74 31 2e 62 69 6e 22 29 } //1 .Namespace(ZipFolder).CopyHere oApp.Namespace(ZipName).items.Item("xl\embeddings\oleObject1.bin")
		$a_01_4 = {5a 69 70 46 6f 6c 64 65 72 } //1 ZipFolder
		$a_01_5 = {62 69 6e 22 2c } //1 bin",
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}