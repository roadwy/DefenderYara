
rule PWS_Win32_Racoon_AD_MTB{
	meta:
		description = "PWS:Win32/Racoon.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 17 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 48 74 74 70 53 65 74 4f 70 74 69 6f 6e } //1 WinHttpSetOption
		$a_01_1 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_2 = {44 65 63 6f 64 65 50 6f 69 6e 74 65 72 } //1 DecodePointer
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_4 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 57 69 74 68 54 6f 6b 65 6e 57 } //1 CreateProcessWithTokenW
		$a_01_5 = {57 69 6e 48 74 74 70 51 75 65 72 79 44 61 74 61 41 76 61 69 6c 61 62 6c 65 } //1 WinHttpQueryDataAvailable
		$a_01_6 = {77 69 6c 64 20 73 63 61 6e } //1 wild scan
		$a_01_7 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //1 GetLastActivePopup
		$a_01_8 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 44 61 74 61 } //1 CryptUnprotectData
		$a_01_9 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 57 } //1 Process32NextW
		$a_01_10 = {43 72 65 61 74 65 43 6f 6d 70 61 74 69 62 6c 65 44 43 } //1 CreateCompatibleDC
		$a_01_11 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //1 CreateProcessA
		$a_01_12 = {47 6c 6f 62 61 6c 4d 65 6d 6f 72 79 53 74 61 74 75 73 45 78 } //1 GlobalMemoryStatusEx
		$a_01_13 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_14 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 54 72 61 6e 73 61 63 74 65 64 41 } //1 CreateDirectoryTransactedA
		$a_01_15 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //1 AppPolicyGetProcessTerminationMethod
		$a_01_16 = {6e 65 74 77 6f 72 6b 20 72 65 73 65 74 } //1 network reset
		$a_01_17 = {47 65 74 53 79 73 74 65 6d 50 6f 77 65 72 53 74 61 74 75 73 } //1 GetSystemPowerStatus
		$a_01_18 = {57 69 6e 48 74 74 70 52 65 61 64 44 61 74 61 } //1 WinHttpReadData
		$a_01_19 = {42 43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //1 BCryptDestroyKey
		$a_01_20 = {43 72 65 61 74 65 54 72 61 6e 73 61 63 74 69 6f 6e } //1 CreateTransaction
		$a_01_21 = {43 6f 6d 6d 69 74 54 72 61 6e 73 61 63 74 69 6f 6e } //1 CommitTransaction
		$a_01_22 = {57 69 6e 48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 } //1 WinHttpSendRequest
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1) >=23
 
}