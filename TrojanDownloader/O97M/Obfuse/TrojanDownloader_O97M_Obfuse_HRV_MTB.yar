
rule TrojanDownloader_O97M_Obfuse_HRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 70 75 74 65 72 32 20 3d 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 77 22 } //1 computer2 = "t" + "t" + "p" + ":" + "/" + "/" + "w" + "w" + "w"
		$a_01_1 = {43 61 6c 6c 20 5f 0d 0a 53 68 65 6c 6c 20 5f 0d 0a 28 70 29 } //1
		$a_01_2 = {63 6f 6d 70 75 74 65 72 33 20 3d 20 22 2e 6a 2e 6d 70 2f } //1 computer3 = ".j.mp/
		$a_01_3 = {70 20 3d 20 6d 6f 64 65 2e 63 6f 6d 70 75 74 65 72 20 2b 20 6d 6f 64 65 2e 63 6f 6d 70 75 74 65 72 32 20 2b 20 6d 6f 64 65 2e 63 6f 6d 70 75 74 65 72 33 } //1 p = mode.computer + mode.computer2 + mode.computer3
		$a_01_4 = {49 6e 70 75 74 42 6f 78 20 22 50 61 73 73 77 6f 72 64 21 22 3a 20 4d 73 67 42 6f 78 20 22 45 52 52 4f 52 21 20 50 61 73 73 77 6f 72 64 20 49 6e 63 6f 72 72 65 63 74 21 22 } //1 InputBox "Password!": MsgBox "ERROR! Password Incorrect!"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}