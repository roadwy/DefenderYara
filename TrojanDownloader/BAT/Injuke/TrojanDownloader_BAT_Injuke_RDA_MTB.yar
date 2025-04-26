
rule TrojanDownloader_BAT_Injuke_RDA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Injuke.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {36 64 62 35 36 63 39 61 2d 32 39 62 66 2d 34 37 37 30 2d 62 33 36 31 2d 30 65 62 39 32 38 36 31 64 30 30 37 } //1 6db56c9a-29bf-4770-b361-0eb92861d007
		$a_01_1 = {54 72 61 66 66 69 63 20 6d 6f 6e 69 74 6f 72 69 6e 67 20 61 70 70 6c 69 63 61 74 69 6f 6e } //1 Traffic monitoring application
		$a_01_2 = {73 46 5a 36 73 43 46 4f 4f 65 32 39 48 52 42 6c 35 6b 2e 32 5a 57 51 30 37 53 58 74 63 46 33 41 4c 6b 6a 32 45 } //1 sFZ6sCFOOe29HRBl5k.2ZWQ07SXtcF3ALkj2E
		$a_01_3 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_4 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //1 LoadLibrary
		$a_01_5 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_6 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //1 GetDelegateForFunctionPointer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}