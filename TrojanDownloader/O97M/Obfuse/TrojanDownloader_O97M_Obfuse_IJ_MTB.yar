
rule TrojanDownloader_O97M_Obfuse_IJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 6a 73 22 } //1 .js"
		$a_03_1 = {2b 20 22 5c 22 20 2b 20 [0-24] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } //1
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 77 69 6e 64 69 72 22 29 20 2b 20 22 5c 54 65 6d 70 22 } //1 = Environ("windir") + "\Temp"
		$a_03_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 20 28 [0-30] 20 2b 20 22 5c 22 20 2b } //1
		$a_01_4 = {2e 43 6f 6e 74 72 6f 6c 73 28 30 29 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //1 .Controls(0).ControlTipText
		$a_01_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Obfuse_IJ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6f 63 6e 65 2d 20 6e 65 64 64 69 68 20 65 6c 79 74 73 77 6f 64 6e 69 77 2d 20 6c 6c 65 68 73 72 65 77 6f 70 } //1 ocne- neddih elytswodniw- llehsrewop
		$a_00_1 = {61 41 49 45 41 67 41 51 5a 41 77 47 41 31 42 41 5a 41 38 47 41 4e 42 51 4c 41 51 48 41 79 42 77 62 41 41 48 41 74 42 51 53 } //1 aAIEAgAQZAwGA1BAZA8GANBQLAQHAyBwbAAHAtBQS
		$a_00_2 = {4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 Object("winmgmts:root\cimv2:Win32_Process")
		$a_00_3 = {73 61 76 65 74 6f 66 69 6c 65 20 46 69 6c 65 50 61 74 68 20 26 20 46 69 6c 65 4e 61 6d 65 20 26 20 22 2e 76 63 66 22 } //1 savetofile FilePath & FileName & ".vcf"
		$a_02_4 = {55 73 65 64 52 61 6e 67 65 2e 52 6f 77 73 2e 43 6f 75 6e 74 [0-09] 73 68 65 65 74 [0-0f] 72 6f 77 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}