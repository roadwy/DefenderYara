
rule TrojanDownloader_O97M_Obfuse_GN{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GN,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 6f 6c 6f 20 3d 20 22 53 68 65 22 20 26 20 22 6c 6c 22 } //1 Polo = "She" & "ll"
		$a_01_1 = {46 61 6b 65 20 3d 20 43 68 72 28 33 32 29 20 26 20 22 2f 22 20 26 20 22 65 22 20 26 20 22 3a 22 } //1 Fake = Chr(32) & "/" & "e" & ":"
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 46 75 6c 6c 4e 61 6d 65 2c 20 22 2e 64 6f 63 6d 22 2c 20 22 2e 72 74 66 22 29 } //1 = Replace(ThisDocument.FullName, ".docm", ".rtf")
		$a_01_3 = {56 42 41 2e 43 61 6c 6c 42 79 4e 61 6d 65 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 50 6f 6c 6f 20 26 20 22 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2c 20 43 6f 70 79 32 2c 20 56 62 4d 65 74 68 6f 64 2c 20 22 57 22 20 26 20 4d 69 78 32 2c 20 46 61 6b 65 } //1 VBA.CallByName VBA.CreateObject(Polo & ".Application"), Copy2, VbMethod, "W" & Mix2, Fake
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}