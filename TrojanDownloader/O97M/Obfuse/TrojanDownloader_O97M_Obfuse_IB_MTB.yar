
rule TrojanDownloader_O97M_Obfuse_IB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 41 70 70 2e 4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 2b 20 22 5c 66 65 6c 6c 64 69 73 74 61 6e 63 65 79 65 61 72 73 68 69 70 6d 65 6e 74 6d 69 6e 6f 72 69 74 79 70 6c 61 73 74 69 63 73 2e 65 78 65 22 } //01 00  ShellApp.Open Environ("TMP") + "\felldistanceyearshipmentminorityplastics.exe"
		$a_01_1 = {22 68 74 74 70 3a 2f 2f 22 20 26 20 22 31 78 76 34 2e 63 6f 6d 2f 64 75 65 2e 6a 70 67 22 2c } //00 00  "http://" & "1xv4.com/due.jpg",
	condition:
		any of ($a_*)
 
}