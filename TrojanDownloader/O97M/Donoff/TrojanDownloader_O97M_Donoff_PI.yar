
rule TrojanDownloader_O97M_Donoff_PI{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PI,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {78 48 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 [0-02] 3a 2f 2f [0-30] 2f [0-20] 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //1
		$a_00_1 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 4c 6f 6f 43 69 70 68 65 72 2e 65 78 65 22 2c 20 32 } //1 .savetofile "LooCipher.exe", 2
		$a_00_2 = {53 68 65 6c 6c 20 28 22 4c 6f 6f 43 69 70 68 65 72 2e 65 78 65 22 29 } //1 Shell ("LooCipher.exe")
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}