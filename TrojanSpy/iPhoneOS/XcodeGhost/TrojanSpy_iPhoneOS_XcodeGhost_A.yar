
rule TrojanSpy_iPhoneOS_XcodeGhost_A{
	meta:
		description = "TrojanSpy:iPhoneOS/XcodeGhost.A,SIGNATURE_TYPE_MACHOHSTR_EXT,16 00 16 00 13 00 00 "
		
	strings :
		$a_01_0 = {73 65 74 48 69 64 64 65 6e 3a } //1 setHidden:
		$a_01_1 = {45 6e 63 72 79 70 74 3a } //1 Encrypt:
		$a_01_2 = {61 70 70 65 6e 64 44 61 74 61 3a } //1 appendData:
		$a_01_3 = {6f 70 65 6e 55 52 4c 3a } //1 openURL:
		$a_01_4 = {63 6f 6e 6e 65 63 74 69 6f 6e 3a 64 69 64 52 65 63 65 69 76 65 44 61 74 61 3a } //1 connection:didReceiveData:
		$a_01_5 = {63 6f 6e 6e 65 63 74 69 6f 6e 44 69 64 46 69 6e 69 73 68 4c 6f 61 64 69 6e 67 } //1 connectionDidFinishLoading
		$a_01_6 = {4c 61 75 6e 63 68 00 52 65 73 69 67 6e } //1
		$a_01_7 = {50 4f 53 54 00 25 6c 75 00 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 } //1
		$a_00_8 = {42 75 6e 64 6c 65 49 44 } //1 BundleID
		$a_00_9 = {54 69 6d 65 73 74 61 6d 70 } //1 Timestamp
		$a_00_10 = {4f 53 56 65 72 73 69 6f 6e } //1 OSVersion
		$a_00_11 = {44 65 76 69 63 65 54 79 70 65 } //1 DeviceType
		$a_00_12 = {4c 61 6e 67 75 61 67 65 } //1 Language
		$a_00_13 = {43 6f 75 6e 74 72 79 43 6f 64 65 } //1 CountryCode
		$a_00_14 = {57 69 66 69 } //1 Wifi
		$a_00_15 = {77 69 66 69 00 33 47 00 74 69 6d 65 73 74 61 6d 70 00 61 70 70 00 62 75 6e 64 6c 65 00 6e 61 6d 65 00 6f 73 00 74 79 70 65 00 73 74 61 74 75 73 00 6c 61 6e 67 75 61 67 65 00 63 6f 75 6e 74 72 79 00 69 64 66 76 00 6e 65 74 77 6f 72 6b 00 76 65 72 73 69 6f 6e } //5 楷楦㌀G楴敭瑳浡p灡p畢摮敬渀浡e獯琀灹e瑳瑡獵氀湡畧条e潣湵牴y摩癦渀瑥潷歲瘀牥楳湯
		$a_00_16 = {68 74 74 70 3a 2f 2f 69 6e 69 74 2e 69 63 6c 6f 75 64 2d 61 6e 61 6c 79 73 69 73 2e 63 6f 6d } //10 http://init.icloud-analysis.com
		$a_01_17 = {68 00 74 00 70 00 73 00 3a 00 2f 00 69 00 6e 00 2e 00 63 00 72 00 61 00 2d 00 6c 00 79 00 6f 00 6d 00 75 00 64 00 67 00 } //10 htps:/in.cra-lyomudg
		$a_01_18 = {68 00 65 00 61 00 64 00 72 00 62 00 6f 00 79 00 70 00 49 00 44 00 63 00 6e 00 6c 00 66 00 69 00 6d 00 76 00 75 00 } //10 headrboypIDcnlfimvu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*5+(#a_00_16  & 1)*10+(#a_01_17  & 1)*10+(#a_01_18  & 1)*10) >=22
 
}