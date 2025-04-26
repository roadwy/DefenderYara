
rule TrojanDownloader_O97M_Obfuse_RVBA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 4e 77 53 28 29 2e 45 78 65 63 20 22 50 6f 77 65 22 20 2b 20 67 6d 32 20 2b 20 67 6d 33 20 2b 20 67 6d 34 } //1 KNwS().Exec "Powe" + gm2 + gm3 + gm4
		$a_01_1 = {78 4f 75 74 20 26 20 56 42 41 2e 4d 69 64 28 78 56 61 6c 75 65 2c 20 69 2c 20 31 29 } //1 xOut & VBA.Mid(xValue, i, 1)
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 68 68 67 74 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_3 = {55 73 65 72 46 6f 72 6d 31 2e 69 71 58 47 70 50 28 67 31 29 } //1 UserForm1.iqXGpP(g1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}