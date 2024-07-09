
rule TrojanDownloader_BAT_Tiny_AT_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 02 6f ?? 00 00 0a 00 08 03 6f ?? 00 00 0a 00 08 16 6f ?? 00 00 0a 00 08 17 6f ?? 00 00 0a 00 08 17 6f ?? 00 00 0a 00 08 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_BAT_Tiny_AT_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 03 00 00 0a 0a 06 6f 04 00 00 0a 72 01 00 00 70 6f 05 00 00 0a 06 6f 04 00 00 0a 72 11 00 00 70 6f 06 00 00 0a 06 6f 04 00 00 0a 17 6f 07 00 00 0a 06 6f 04 00 00 0a 17 6f 08 00 00 0a 06 6f 09 00 00 0a 26 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_BAT_Tiny_AT_MTB_3{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 00 08 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 07 09 28 ?? 00 00 0a 00 00 de 0b } //2
		$a_01_1 = {57 69 6e 64 6f 77 73 53 65 74 75 70 4d 61 6e 67 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 57 69 6e 64 6f 77 73 53 65 74 75 70 4d 61 6e 67 65 72 2e 70 64 62 } //1 WindowsSetupManger\obj\Debug\WindowsSetupManger.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule TrojanDownloader_BAT_Tiny_AT_MTB_4{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 11 04 16 9a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 06 11 05 11 04 17 9a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 07 11 06 11 06 6f ?? ?? ?? 0a 17 59 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 08 28 ?? ?? ?? 0a 11 08 6f ?? ?? ?? 0a 13 06 11 06 11 07 } //2
		$a_01_1 = {64 00 65 00 2d 00 43 00 48 00 2d 00 70 00 6c 00 65 00 61 00 73 00 65 00 6e 00 6f 00 72 00 75 00 6e 00 } //1 de-CH-pleasenorun
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}