
rule TrojanDownloader_O97M_Obfuse_PYRT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PYRT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 2e 50 72 6f 63 65 64 75 72 65 63 61 6c 6c } //1 obj.Procedurecall
		$a_01_1 = {68 6f 6e 65 20 74 68 65 20 73 68 65 6c 6c 65 64 20 61 70 70 6c 69 63 61 74 69 6f 6e 3a } //1 hone the shelled application:
		$a_01_2 = {52 65 74 75 72 6e 56 61 6c 75 65 20 3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 30 26 2c 20 63 6d 64 6c 69 6e 65 24 2c 20 30 26 2c 20 30 26 2c 20 31 26 2c 20 5f } //1 ReturnValue = CreateProcessA(0&, cmdline$, 0&, 0&, 1&, _
		$a_01_3 = {4e 4f 52 4d 41 4c 5f 50 52 49 4f 52 49 54 59 5f 43 4c 41 53 53 2c 20 30 26 2c 20 30 26 2c 20 68 6f 6e 65 2c 20 6d 6f 6e 65 29 } //1 NORMAL_PRIORITY_CLASS, 0&, 0&, hone, mone)
		$a_01_4 = {61 72 72 61 79 6d 61 69 6e 28 69 29 2e 62 61 72 63 6f 64 65 20 3d 20 22 6d 73 68 74 61 20 22 } //1 arraymain(i).barcode = "mshta "
		$a_03_5 = {3d 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 [0-0f] 77 64 69 61 68 73 69 64 68 22 } //1
		$a_01_6 = {6f 62 6a 2e 53 55 53 53 59 42 41 4b 41 20 28 62 6f 62 61 20 2b 20 62 6f 62 32 20 2b 20 62 6f 62 33 29 } //1 obj.SUSSYBAKA (boba + bob2 + bob3)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}