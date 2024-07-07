
rule TrojanDownloader_BAT_QuasarRAT_D_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 2b 3e 2b 43 16 2d 2e 2b 41 72 90 01 03 70 2b 3d 2b 42 16 2d 0d 2b 40 14 14 2b 3f 74 90 01 01 00 00 01 2b 3f 08 28 90 01 01 00 00 0a 16 fe 01 0d 09 2c 0a 08 28 90 00 } //2
		$a_01_1 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_2 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_01_3 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}