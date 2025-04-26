
rule Trojan_BAT_AgentTesla_IE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_02_0 = {8e 69 17 da 0c 16 0d ?? ?? 05 2b ?? 06 ?? ?? ?? ?? ?? 09 06 ?? ?? ?? ?? ?? 09 91 7e ?? ?? ?? ?? 7e ?? ?? ?? ?? 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 07 09 28 ?? ?? ?? ?? 9c ?? 13 05 38 ?? ff ff ff 09 17 d6 0d ?? 13 05 38 ?? ff ff ff 09 08 } //10
		$a_02_1 = {8e 69 17 da 0c 16 ?? 2b ?? 06 09 06 09 91 7e ?? ?? ?? ?? 7e ?? ?? ?? ?? 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 07 09 28 ?? ?? ?? ?? 9c 09 17 d6 0d 09 08 31 d7 } //10
		$a_80_2 = {57 65 62 52 65 73 70 6f 6e 73 65 } //WebResponse  1
		$a_80_3 = {47 65 74 52 65 73 70 6f 6e 73 65 } //GetResponse  1
		$a_80_4 = {57 65 62 52 65 71 75 65 73 74 } //WebRequest  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=13
 
}
rule Trojan_BAT_AgentTesla_IE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.IE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 10 00 00 "
		
	strings :
		$a_01_0 = {67 67 76 45 4f 76 70 45 62 68 56 36 55 4f 6d 6d 30 35 } //10 ggvEOvpEbhV6UOmm05
		$a_01_1 = {58 4e 54 62 6c 38 56 62 6b 73 38 73 66 66 75 49 79 41 } //10 XNTbl8Vbks8sffuIyA
		$a_01_2 = {55 69 39 6d 48 79 75 62 68 46 61 70 71 52 58 34 64 64 } //10 Ui9mHyubhFapqRX4dd
		$a_01_3 = {70 31 63 31 43 42 37 79 78 6a 33 74 56 4e 69 68 36 31 } //10 p1c1CB7yxj3tVNih61
		$a_01_4 = {6b 66 39 53 43 74 63 78 34 69 57 51 4b 49 69 47 69 57 } //10 kf9SCtcx4iWQKIiGiW
		$a_01_5 = {61 43 61 44 4c 61 5a 56 75 72 45 62 30 42 46 36 5a 75 } //10 aCaDLaZVurEb0BF6Zu
		$a_01_6 = {6e 57 6d 48 73 48 63 5a 6f 68 53 59 49 58 75 67 47 42 50 } //10 nWmHsHcZohSYIXugGBP
		$a_01_7 = {56 66 4a 71 65 4f 63 58 39 38 67 33 41 64 54 4b 73 34 6d } //10 VfJqeOcX98g3AdTKs4m
		$a_01_8 = {71 75 72 52 44 6b 63 48 4c 6c 56 48 32 70 73 63 47 76 69 } //10 qurRDkcHLlVH2pscGvi
		$a_01_9 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //1 kLjw4iIsCLsZtxc4lksN0j
		$a_01_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_11 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_12 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_13 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_14 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_15 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=37
 
}