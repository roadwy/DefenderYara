
rule Spyware_Win32_Navihelper{
	meta:
		description = "Spyware:Win32/Navihelper,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //1 Microsoft Visual C++ Runtime Library
		$a_80_1 = {4e 61 76 69 48 65 6c 70 65 72 2e 44 4c 4c } //NaviHelper.DLL  1
		$a_01_2 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
		$a_00_3 = {49 6e 74 65 72 6e 65 74 53 65 74 43 6f 6f 6b 69 65 41 } //1 InternetSetCookieA
		$a_00_4 = {31 00 33 00 46 00 41 00 43 00 41 00 36 00 32 00 2d 00 35 00 46 00 43 00 34 00 2d 00 34 00 38 00 31 00 37 00 2d 00 39 00 31 00 37 00 35 00 2d 00 39 00 43 00 38 00 44 00 30 00 30 00 39 00 37 00 35 00 39 00 31 00 36 00 } //1 13FACA62-5FC4-4817-9175-9C8D00975916
		$a_00_5 = {53 68 61 72 65 64 4d 65 6d 6f 72 79 4d 75 74 65 78 } //1 SharedMemoryMutex
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}