
rule TrojanDownloader_Win64_Travnet_MTB{
	meta:
		description = "TrojanDownloader:Win64/Travnet!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 10 00 00 "
		
	strings :
		$a_01_0 = {48 66 75 4e 70 65 76 6d 66 47 6a 6d 66 4f 62 6e 66 42 } //1 HfuNpevmfGjmfObnfB
		$a_01_1 = {68 69 20 75 72 20 69 6e 20 31 73 74 } //1 hi ur in 1st
		$a_01_2 = {4b 65 79 20 73 69 7a 65 20 69 73 20 25 64 } //1 Key size is %d
		$a_01_3 = {50 6b 65 79 20 52 65 73 6f 75 72 63 65 20 32 20 73 75 63 63 65 73 73 } //1 Pkey Resource 2 success
		$a_01_4 = {55 73 61 67 65 3a 20 69 6e 6a 65 63 74 2e 65 78 65 20 5b } //1 Usage: inject.exe [
		$a_01_5 = {55 73 61 67 65 3a 20 69 6e 6a 65 63 74 20 45 58 45 20 5b } //1 Usage: inject EXE [
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_7 = {45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 } //1 EncodePointer
		$a_01_8 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_9 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_10 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //1 QueryPerformanceCounter
		$a_01_11 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } //1 GetCurrentProcessId
		$a_01_12 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //1 GetCurrentThreadId
		$a_01_13 = {47 65 74 53 79 73 74 65 6d 54 69 6d 65 41 73 46 69 6c 65 54 69 6d 65 } //1 GetSystemTimeAsFileTime
		$a_01_14 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 57 } //1 OutputDebugStringW
		$a_01_15 = {6d 65 6d 73 65 74 } //1 memset
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=15
 
}