
rule Trojan_BAT_PrivateLoader_NV_MTB{
	meta:
		description = "Trojan:BAT/PrivateLoader.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_81_0 = {51 58 4e 7a 5a 57 31 69 62 48 6c 4d 62 32 46 6b 5a 58 4a 42 } //2 QXNzZW1ibHlMb2FkZXJB
		$a_81_1 = {55 33 6c 7a 64 47 56 74 53 57 35 6d 62 30 46 42 } //1 U3lzdGVtSW5mb0FB
		$a_81_2 = {55 6b 52 51 53 57 35 7a 64 47 46 73 62 47 56 79 51 55 46 42 } //1 UkRQSW5zdGFsbGVyQUFB
		$a_81_3 = {55 6b 52 51 51 33 4a 6c 59 58 52 76 63 6c 39 51 63 6d 39 6a 5a 58 4e 7a 5a 57 52 43 65 55 5a 76 5a 48 6c 42 } //1 UkRQQ3JlYXRvcl9Qcm9jZXNzZWRCeUZvZHlB
		$a_81_4 = {30 78 62 31 31 61 31 } //1 0xb11a1
		$a_81_5 = {55 70 6c 6f 61 64 56 61 6c 75 65 73 } //1 UploadValues
		$a_81_6 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 54 61 73 6b 41 73 79 6e 63 } //1 DownloadFileTaskAsync
		$a_81_7 = {49 73 50 6f 72 74 4f 70 65 6e } //1 IsPortOpen
		$a_81_8 = {53 65 6e 64 43 72 65 64 65 6e 74 69 61 6c 73 } //1 SendCredentials
		$a_81_9 = {47 65 6e 65 72 61 74 65 52 61 6e 64 6f 6d 50 61 73 73 77 6f 72 64 } //1 GenerateRandomPassword
		$a_81_10 = {41 64 64 55 73 65 72 54 6f 52 65 6d 6f 74 65 44 65 73 6b 74 6f 70 47 72 6f 75 70 } //1 AddUserToRemoteDesktopGroup
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=12
 
}