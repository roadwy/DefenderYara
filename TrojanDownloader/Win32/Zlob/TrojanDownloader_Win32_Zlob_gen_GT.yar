
rule TrojanDownloader_Win32_Zlob_gen_GT{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!GT,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {56 57 53 55 e8 00 00 00 00 5d 81 ed 49 2b 40 00 e8 03 02 00 00 e8 b7 06 00 00 b8 00 00 00 00 85 c0 75 21 ff 85 5b 2b 40 00 e8 63 01 00 00 60 8d b5 40 2b 40 00 b9 f2 09 00 00 89 c7 f3 a4 61 83 c0 04 ff e0 60 8b bd 3c 30 40 00 03 bd 14 30 40 00 8d b5 e2 32 40 00 8b 8d fc 2f 40 00 68 00 10 00 00 57 e8 60 01 00 00 f3 a4 8d 85 d2 32 40 00 8b 9d 14 30 40 00 ff b5 18 30 40 00 ff b5 0c 30 40 00 6a 01 50 53 e8 7d 04 00 00 ff b5 40 30 40 00 ff b5 14 30 40 00 e8 79 00 00 00 8b 85 00 30 40 00 85 c0 74 1c } //1
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 41 } //1 URLDownloadA
		$a_01_2 = {43 6f 6d 70 61 72 65 53 65 63 75 72 69 74 79 49 64 73 } //1 CompareSecurityIds
		$a_01_3 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_01_4 = {46 69 6e 64 46 69 72 73 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 57 } //1 FindFirstUrlCacheEntryW
		$a_01_5 = {46 74 70 52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 41 } //1 FtpRemoveDirectoryA
		$a_01_6 = {46 74 70 53 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 41 } //1 FtpSetCurrentDirectoryA
		$a_01_7 = {46 6f 72 63 65 4e 65 78 75 73 4c 6f 6f 6b 75 70 45 78 57 } //1 ForceNexusLookupExW
		$a_01_8 = {00 00 00 00 63 61 60 0c 64 62 61 2b 6c 6a 69 4c 74 72 71 64 74 72 71 6e 72 70 70 6f 6b 69 69 69 5c 5b 5a 58 54 52 51 43 55 53 52 2a 5a 58 58 13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 69 67 66 18 81 7f 7e 62 a3 a1 a0 ac bc ba b9 d6 c7 c6 c4 ee cc ca c9 fa ca c8 c7 fb cc cb ca fb ce cc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}