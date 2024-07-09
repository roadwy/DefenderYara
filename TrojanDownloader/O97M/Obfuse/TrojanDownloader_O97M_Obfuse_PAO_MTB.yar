
rule TrojanDownloader_O97M_Obfuse_PAO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 76 69 61 2e 68 79 70 6f 74 68 65 73 2e 69 73 2f 62 6f 79 61 6d 61 2e 6d 65 64 79 61 6e 65 66 2e 63 6f 6d 2f 76 65 6e 64 6f 72 2f 68 61 6d 63 72 65 73 74 2f 66 69 6c 65 73 2f 70 68 79 5f 5f 31 5f 5f 33 31 36 32 39 5f 5f 32 36 34 39 30 39 34 36 37 34 5f 5f 31 36 30 35 36 34 32 36 31 32 2e 65 78 65 } //1 https://via.hypothes.is/boyama.medyanef.com/vendor/hamcrest/files/phy__1__31629__2649094674__1605642612.exe
		$a_03_1 = {73 74 61 72 74 20 [0-10] 25 54 4d 50 25 5c 31 30 30 72 6e 2e 65 78 65 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}