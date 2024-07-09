
rule Trojan_BAT_RedLineStealer_AW_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_03_0 = {33 28 07 6f 60 ?? ?? 0a 28 d3 ?? ?? 06 2d 1b 07 6f 60 ?? ?? 0a 28 62 ?? ?? 0a 2d 0e 07 6f 60 ?? ?? 0a 6f d2 ?? ?? 0a 0c de 31 06 6f 03 ?? ?? 0a 2d bb 90 0a 45 00 06 6f 5f ?? ?? 0a 0b 07 6f 60 ?? ?? 0a 6f 61 ?? ?? 0a 18 } //1
		$a_01_1 = {72 ab 0f 00 70 20 98 3a 00 00 28 d5 00 00 06 0c de 0b } //1
		$a_01_2 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //1 GetTempFileName
		$a_01_3 = {43 68 72 6f 6d 65 47 65 74 4e 61 6d 65 } //1 ChromeGetName
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_5 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_6 = {47 65 74 47 72 61 70 68 69 63 43 61 72 64 73 } //1 GetGraphicCards
		$a_01_7 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } //1 GetDirectories
		$a_01_8 = {47 65 74 46 69 6c 65 73 } //1 GetFiles
		$a_01_9 = {67 65 74 5f 47 61 74 65 77 61 79 41 64 64 72 65 73 73 65 73 } //1 get_GatewayAddresses
		$a_01_10 = {62 72 6f 77 73 65 72 50 61 74 68 73 } //1 browserPaths
		$a_01_11 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_01_12 = {63 68 72 6f 6d 65 4b 65 79 } //1 chromeKey
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}