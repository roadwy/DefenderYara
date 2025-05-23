
rule Trojan_BAT_FileCoder_B_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 13 00 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 50 65 72 73 6f 6e 61 6c 49 44 } //1 get_PersonalID
		$a_81_1 = {47 65 74 53 79 73 74 65 6d 49 44 } //1 GetSystemID
		$a_81_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_3 = {67 65 74 5f 54 61 73 6b } //1 get_Task
		$a_81_4 = {67 65 74 5f 64 69 73 6b } //1 get_disk
		$a_81_5 = {45 6e 63 72 79 70 74 69 6f 6e } //1 Encryption
		$a_81_6 = {73 65 74 5f 50 65 72 73 69 73 74 4b 65 79 } //1 set_PersistKey
		$a_81_7 = {53 74 61 72 74 75 70 } //1 Startup
		$a_81_8 = {67 65 74 5f 46 69 6c 65 73 } //1 get_Files
		$a_81_9 = {73 65 74 5f 46 69 6c 65 73 } //1 set_Files
		$a_81_10 = {52 75 6e 45 6e 63 72 79 70 74 } //1 RunEncrypt
		$a_81_11 = {41 65 73 45 6e 63 72 79 70 74 } //1 AesEncrypt
		$a_81_12 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_81_13 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_14 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_15 = {52 65 61 64 41 6c 6c 54 65 78 74 } //1 ReadAllText
		$a_81_16 = {57 72 69 74 65 41 6c 6c 54 65 78 74 } //1 WriteAllText
		$a_81_17 = {47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 } //1 GetEntryAssembly
		$a_81_18 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 } //1 CreateDirectory
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1+(#a_81_18  & 1)*1) >=19
 
}