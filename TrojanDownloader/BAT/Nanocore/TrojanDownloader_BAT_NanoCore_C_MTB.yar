
rule TrojanDownloader_BAT_NanoCore_C_MTB{
	meta:
		description = "TrojanDownloader:BAT/NanoCore.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 0e 00 00 "
		
	strings :
		$a_01_0 = {00 11 01 20 80 f9 37 03 6f 03 00 00 0a 13 02 38 00 00 00 00 dd } //10
		$a_03_1 = {38 00 00 00 00 00 00 11 ?? 16 73 ?? 00 00 0a 73 ?? 00 00 0a 13 90 0a 1d 00 00 00 0a 13 02 } //10
		$a_01_2 = {52 65 70 6c 61 63 65 } //10 Replace
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //10 GetResponseStream
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //10 WebRequest
		$a_01_5 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //10 SecurityProtocolType
		$a_01_6 = {54 6f 41 72 72 61 79 } //10 ToArray
		$a_01_7 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //10 ProcessWindowStyle
		$a_01_8 = {47 65 74 4d 65 74 68 6f 64 } //10 GetMethod
		$a_01_9 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //10 CreateDelegate
		$a_01_10 = {47 65 74 54 79 70 65 73 } //10 GetTypes
		$a_01_11 = {2e 00 6a 00 70 00 67 00 } //1 .jpg
		$a_01_12 = {2e 00 70 00 6e 00 67 00 } //1 .png
		$a_01_13 = {2e 00 62 00 6d 00 70 00 } //1 .bmp
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*10+(#a_01_10  & 1)*10+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=111
 
}