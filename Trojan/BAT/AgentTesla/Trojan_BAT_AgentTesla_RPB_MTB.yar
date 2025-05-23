
rule Trojan_BAT_AgentTesla_RPB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0b 00 00 "
		
	strings :
		$a_00_0 = {34 00 35 00 2e 00 31 00 33 00 37 00 2e 00 32 00 32 00 2e 00 31 00 36 00 33 00 } //10 45.137.22.163
		$a_00_1 = {31 00 38 00 35 00 2e 00 32 00 32 00 32 00 2e 00 35 00 37 00 2e 00 31 00 39 00 39 00 } //10 185.222.57.199
		$a_01_2 = {53 61 6e 64 62 6f 78 69 65 20 53 74 61 72 74 } //3 Sandboxie Start
		$a_01_3 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_4 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
		$a_01_5 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_6 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_7 = {57 72 69 74 65 } //1 Write
		$a_01_8 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_9 = {53 74 6f 70 77 61 74 63 68 } //1 Stopwatch
		$a_01_10 = {53 6c 65 65 70 } //1 Sleep
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=20
 
}
rule Trojan_BAT_AgentTesla_RPB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {00 00 06 6f 17 00 00 0a 0d 12 03 28 18 00 00 0a 23 00 00 00 00 00 00 34 40 fe 04 0c 08 2d e1 } //1
		$a_01_1 = {52 00 65 00 76 00 65 00 72 00 73 00 65 00 } //1 Reverse
		$a_03_2 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-70] 2e 00 70 00 6e 00 67 00 } //1
		$a_01_3 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_4 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //1 HttpWebResponse
		$a_01_5 = {53 74 6f 70 77 61 74 63 68 } //1 Stopwatch
		$a_01_6 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_7 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_RPB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-70] 2e 00 65 00 78 00 65 00 } //1
		$a_01_1 = {41 00 6e 00 74 00 69 00 6d 00 61 00 6c 00 77 00 61 00 72 00 65 00 2e 00 65 00 78 00 65 00 } //1 Antimalware.exe
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_3 = {4e 65 76 65 72 4c 6f 73 65 } //1 NeverLose
		$a_01_4 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
		$a_01_5 = {47 6f 6c 64 65 6e 48 61 63 6b } //1 GoldenHack
		$a_01_6 = {53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //1 SpecialFolder
		$a_01_7 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}