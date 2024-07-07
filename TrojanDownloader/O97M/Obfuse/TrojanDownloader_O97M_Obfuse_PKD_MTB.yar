
rule TrojanDownloader_O97M_Obfuse_PKD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PKD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 58 45 43 20 90 02 05 20 2b 90 00 } //1
		$a_03_1 = {3d 20 56 42 41 2e 52 65 70 6c 61 63 65 28 22 6d 73 68 90 02 05 22 2c 20 22 90 02 05 22 2c 20 22 74 61 22 29 90 00 } //1
		$a_01_2 = {3d 20 22 20 68 74 74 70 3a 2f 2f 6a 2e 6d 70 2f 22 } //1 = " http://j.mp/"
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 22 52 65 2d 49 6e 73 74 61 6c 6c 20 4f 66 66 69 63 65 22 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31 } //1 Debug.Print MsgBox("Re-Install Office", vbOKCancel); returns; 1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}