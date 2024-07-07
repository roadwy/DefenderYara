
rule Trojan_Win32_Sabsik_RF_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {62 6a 58 56 5a 67 72 4d 55 39 51 47 50 73 71 63 67 32 4a 47 64 43 61 4f 43 4b } //1 bjXVZgrMU9QGPsqcg2JGdCaOCK
		$a_81_1 = {6e 76 52 41 64 33 63 6b 72 32 77 79 73 53 57 32 64 32 57 67 61 66 65 72 72 66 75 31 69 63 } //1 nvRAd3ckr2wysSW2d2Wgaferrfu1ic
		$a_81_2 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 UnhookWindowsHookEx
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Sabsik_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Sabsik.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 09 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 73 69 74 61 72 5c 44 65 73 6b 74 6f 70 5c 34 30 20 70 72 6f 6a 65 63 74 73 5c 70 72 6f 6a 65 63 74 5c 70 72 6f 6a 65 63 74 5c 43 6c 61 73 73 69 63 61 6c 20 44 6c 6c 20 49 6e 6a 65 63 74 69 6f 6e 5f 64 6c 6c 5c 54 79 70 69 63 61 6c 20 43 6c 61 73 73 69 63 61 6c 20 44 6c 6c 20 49 6e 6a 65 63 74 69 6f 6e } //10 C:\Users\sitar\Desktop\40 projects\project\project\Classical Dll Injection_dll\Typical Classical Dll Injection
		$a_81_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_2 = {5c 73 68 65 6c 6c 64 6f 63 2e 64 6c 6c } //1 \shelldoc.dll
		$a_81_3 = {47 6c 6f 62 61 6c 5c 52 50 43 4d 75 74 65 78 } //1 Global\RPCMutex
		$a_81_4 = {5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 33 32 6b 2e 73 79 73 } //1 \system32\win32k.sys
		$a_81_5 = {47 65 74 43 50 49 6e 66 6f } //1 GetCPInfo
		$a_81_6 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 57 } //1 OutputDebugStringW
		$a_81_7 = {63 6f 6e 6e 65 63 74 69 6f 6e 5f 61 62 6f 72 74 65 64 } //1 connection_aborted
		$a_81_8 = {63 6f 6e 6e 65 63 74 69 6f 6e 5f 72 65 66 75 73 65 64 } //1 connection_refused
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=15
 
}