
rule TrojanDownloader_BAT_Wagex_ABHX_MTB{
	meta:
		description = "TrojanDownloader:BAT/Wagex.ABHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 29 00 00 0a 72 11 00 00 70 28 2a 00 00 0a 0a 06 28 06 00 00 06 0b 07 28 2b 00 00 0a 0c 08 72 23 00 00 70 6f 2c 00 00 0a 6f 2d 00 00 0a 0d 09 28 2e 00 00 0a 13 04 11 04 16 6f 2f 00 00 0a 74 1b 00 00 01 13 05 11 05 18 6f 2f 00 00 0a 74 1b 00 00 01 13 06 16 13 07 38 fd 00 00 00 } //1
		$a_01_1 = {57 00 6f 00 72 00 6c 00 64 00 43 00 75 00 70 00 54 00 77 00 6f 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 WorldCupTwo.Properties.Resources
		$a_01_2 = {57 00 6f 00 72 00 6c 00 64 00 43 00 75 00 70 00 54 00 77 00 6f 00 2e 00 65 00 78 00 65 00 } //1 WorldCupTwo.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}