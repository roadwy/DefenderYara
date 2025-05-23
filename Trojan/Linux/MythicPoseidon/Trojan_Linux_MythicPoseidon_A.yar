
rule Trojan_Linux_MythicPoseidon_A{
	meta:
		description = "Trojan:Linux/MythicPoseidon.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 16 00 00 "
		
	strings :
		$a_03_0 = {44 0f 11 7c 24 40 48 8d ?? ?? ?? ?? ?? bb 03 00 00 00 48 8b 4c 24 30 48 8b 7c 24 28 [0-05] e8 ?? ?? ?? ff 48 89 44 24 40 48 89 5c 24 48 48 85 c9 0f 85 ?? 00 00 00 48 89 44 24 40 48 89 5c 24 48 48 8b 8c 24 a8 01 00 00 48 8b 41 60 48 8d 5c 24 40 e8 ?? ?? ?? ff 48 8d ?? ?? ?? ?? ?? 48 89 8c 24 80 00 00 00 } //2
		$a_03_1 = {48 89 44 24 20 48 89 44 24 78 48 8b 4c 24 30 48 8b 49 38 48 8b 59 38 48 8b 7c 24 70 48 8b 4c 24 68 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ff 84 00 } //2
		$a_03_2 = {48 89 c2 31 c0 4c 8d ?? ?? ?? ?? ?? 41 b9 01 00 00 00 f0 45 0f b1 08 41 0f 94 c2 45 84 d2 75 ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ff 48 8b 4c 24 48 48 8b 54 24 50 48 8b 5c 24 40 4c 8d ?? ?? ?? ?? ?? 41 b9 01 00 00 00 } //2
		$a_03_3 = {48 83 ec 28 48 89 6c 24 20 48 8d ?? ?? ?? 48 89 44 24 30 48 89 7c 24 48 48 89 74 24 50 48 89 4c 24 40 48 8b 15 ?? ?? ?? ?? 49 89 c0 48 8d ?? ?? ?? ?? ?? 49 89 d9 48 89 d3 4c 89 c1 4c 89 cf } //2
		$a_03_4 = {48 81 ec b8 02 00 00 48 89 ac 24 b0 02 00 00 48 8d ?? ?? ?? ?? ?? 00 44 0f 11 bc 24 a0 02 00 00 c6 44 24 2e 00 48 89 84 24 c0 02 00 00 48 89 9c 24 c8 02 00 00 48 89 8c 24 d0 02 00 00 48 89 bc 24 d8 02 00 00 f2 0f 11 84 24 e0 02 00 00 48 89 b4 24 e8 02 00 00 4c 89 84 24 f0 02 00 00 4c 89 8c 24 f8 02 00 00 } //2
		$a_01_5 = {67 69 74 68 75 62 2e 63 6f 6d 2f 4d 79 74 68 69 63 41 67 65 6e 74 73 } //2 github.com/MythicAgents
		$a_01_6 = {65 55 79 6f 5a 41 49 47 49 62 57 7a 34 4a 78 55 4e 78 6c 32 50 31 49 4d 76 75 62 4b 4d 74 6b 56 63 67 4f 30 78 72 56 35 35 62 73 } //2 eUyoZAIGIbWz4JxUNxl2P1IMvubKMtkVcgO0xrV55bs
		$a_00_7 = {49 44 20 6a 73 6f 6e 3a 22 69 64 22 } //1 ID json:"id"
		$a_00_8 = {49 50 20 6a 73 6f 6e 3a 22 69 70 22 } //1 IP json:"ip"
		$a_00_9 = {6a 73 6f 6e 3a 22 75 72 6c 22 } //1 json:"url"
		$a_01_10 = {68 74 6d 6c 50 6f 73 74 44 61 74 61 } //1 htmlPostData
		$a_01_11 = {53 63 61 6e 50 6f 72 74 52 61 6e 67 65 73 } //1 ScanPortRanges
		$a_01_12 = {53 63 72 65 65 6e 73 68 6f 74 44 61 74 61 } //1 ScreenshotData
		$a_01_13 = {53 65 61 72 63 68 57 69 74 68 54 79 70 65 } //1 SearchWithType
		$a_01_14 = {53 65 74 53 6c 65 65 70 4a 69 74 74 65 72 } //1 SetSleepJitter
		$a_01_15 = {47 65 74 46 69 6c 65 46 72 6f 6d 4d 79 74 68 69 63 } //1 GetFileFromMythic
		$a_01_16 = {53 65 6e 64 46 69 6c 65 54 6f 4d 79 74 68 69 63 } //1 SendFileToMythic
		$a_01_17 = {53 65 74 53 6c 65 65 70 49 6e 74 65 72 76 61 6c } //1 SetSleepInterval
		$a_00_18 = {75 70 6c 6f 61 64 2e 75 70 6c 6f 61 64 41 72 67 73 } //1 upload.uploadArgs
		$a_00_19 = {6b 65 79 73 74 61 74 65 2e 45 76 65 6e 74 54 79 70 65 } //1 keystate.EventType
		$a_00_20 = {6b 65 79 73 74 61 74 65 2e 4b 65 79 4c 6f 67 67 65 72 } //1 keystate.KeyLogger
		$a_00_21 = {6c 69 6e 6b 5f 74 63 70 2e 41 72 67 75 6d 65 6e 74 73 } //1 link_tcp.Arguments
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*1+(#a_00_20  & 1)*1+(#a_00_21  & 1)*1) >=4
 
}