
rule PWS_Win32_Azurlt_MTB{
	meta:
		description = "PWS:Win32/Azurlt!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 19 00 00 01 00 "
		
	strings :
		$a_81_0 = {55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4e 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 56 57 35 70 62 6e 4e 30 59 57 78 73 } //01 00  U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxs
		$a_81_1 = {49 6e 74 65 72 6e 65 74 53 65 74 4f 70 74 69 6f 6e 41 } //01 00  InternetSetOptionA
		$a_81_2 = {52 65 67 43 72 65 61 74 65 4b 65 79 45 78 57 } //01 00  RegCreateKeyExW
		$a_81_3 = {53 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 57 } //01 00  SetEnvironmentVariableW
		$a_81_4 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 73 55 73 65 72 57 } //01 00  CreateProcessAsUserW
		$a_81_5 = {47 6c 6f 62 61 6c 4d 65 6d 6f 72 79 53 74 61 74 75 73 } //01 00  GlobalMemoryStatus
		$a_81_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //01 00  CreateToolhelp32Snapshot
		$a_81_7 = {47 64 69 70 47 65 74 49 6d 61 67 65 45 6e 63 6f 64 65 72 73 53 69 7a 65 } //01 00  GdipGetImageEncodersSize
		$a_81_8 = {53 45 46 53 52 46 64 42 55 6b 56 63 52 45 56 54 51 31 4a 4a 55 46 52 4a 54 30 35 63 55 33 6c 7a 64 47 56 74 58 45 4e 6c 62 6e 52 79 59 57 78 51 63 6d 39 6a 5a 58 4e 7a 62 33 4a 63 4d 41 3d 3d } //01 00  SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA==
		$a_81_9 = {47 44 49 53 63 72 65 65 6e 53 68 6f 74 } //01 00  GDIScreenShot
		$a_81_10 = {43 72 79 70 74 52 65 6c 65 61 73 65 43 6f 6e 74 65 78 74 } //01 00  CryptReleaseContext
		$a_81_11 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 44 61 74 61 } //01 00  CryptUnprotectData
		$a_81_12 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //01 00  HttpOpenRequestA
		$a_81_13 = {50 56 41 55 4c 54 5f 43 52 45 44 38 } //01 00  PVAULT_CRED8
		$a_81_14 = {50 72 6f 63 65 73 73 33 32 4e 65 78 74 57 } //01 00  Process32NextW
		$a_81_15 = {75 46 69 6c 65 46 69 6e 64 65 72 55 } //01 00  uFileFinderU
		$a_81_16 = {75 49 45 37 5f 64 65 63 6f 64 65 55 } //01 00  uIE7_decodeU
		$a_81_17 = {50 61 73 73 77 6f 72 64 73 4c 69 73 74 2e 74 78 74 } //01 00  PasswordsList.txt
		$a_81_18 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //01 00  ShellExecuteExW
		$a_81_19 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 41 } //01 00  GetLogicalDriveStringsA
		$a_81_20 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_81_21 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //01 00  HttpSendRequestA
		$a_81_22 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 41 } //01 00  InternetCrackUrlA
		$a_81_23 = {48 74 74 70 41 64 64 52 65 71 75 65 73 74 48 65 61 64 65 72 73 41 } //01 00  HttpAddRequestHeadersA
		$a_81_24 = {42 72 6f 77 73 65 72 73 5c 43 6f 6f 6b 69 65 73 } //00 00  Browsers\Cookies
	condition:
		any of ($a_*)
 
}