
rule TrojanDownloader_Linux_Adnel_I{
	meta:
		description = "TrojanDownloader:Linux/Adnel.I,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 66 73 30 35 6e 35 2e 73 65 6e 64 73 70 61 63 65 2e 63 6f 6d 2f 64 6c 2f 38 66 33 35 30 63 61 64 62 38 31 34 30 62 37 37 36 62 35 34 34 30 37 33 33 34 32 34 31 31 62 61 2f 35 36 31 34 33 34 65 38 36 61 33 66 36 34 36 65 2f 71 6e 34 6a 36 6e 2f 32 32 32 32 32 32 32 32 32 32 32 32 32 2e 65 78 65 } //1 /fs05n5.sendspace.com/dl/8f350cadb8140b776b544073342411ba/561434e86a3f646e/qn4j6n/2222222222222.exe
		$a_01_1 = {45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 5c 22 20 26 20 22 } //1 Environ("AppData") & "\" & "
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}