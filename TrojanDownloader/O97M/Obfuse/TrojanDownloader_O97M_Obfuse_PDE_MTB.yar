
rule TrojanDownloader_O97M_Obfuse_PDE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PDE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 65 6e 76 69 72 6f 6e 24 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 26 22 5c 22 26 } //01 00  =environ$("userprofile")&"\"&
		$a_01_1 = {3d 63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 } //01 00  =chr(50)+chr(48)+chr(48)
		$a_03_2 = {73 70 65 63 69 61 6c 70 61 74 68 3d 77 73 68 73 68 65 6c 6c 2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 22 90 02 0a 22 29 90 00 } //01 00 
		$a_03_3 = {3d 73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 90 02 0a 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 90 00 } //01 00 
		$a_01_4 = {28 22 66 79 66 2f 64 64 6e 6e 22 29 } //01 00  ("fyf/ddnn")
		$a_01_5 = {66 79 66 2f 6e 70 70 67 68 79 6e 6b 63 6f 64 6e 6b 67 65 69 68 67 65 74 69 67 6a 70 75 73 71 64 30 6f 67 35 6f 73 6b 68 6b 73 31 31 31 31 6e 75 71 70 75 6a 75 76 75 73 67 65 68 65 74 68 67 30 6e 70 64 2f 74 62 6f 6a 65 6f 62 73 70 75 64 62 73 75 30 30 3b 74 71 75 75 69 } //01 00  fyf/nppghynkcodnkgeihgetigjpusqd0og5oskhks1111nuqpujuvusgehethg0npd/tbojeobspudbsu00;tquui
		$a_01_6 = {72 61 6e 67 65 28 22 61 31 22 29 2e 76 61 6c 75 65 3d 22 } //00 00  range("a1").value="
	condition:
		any of ($a_*)
 
}