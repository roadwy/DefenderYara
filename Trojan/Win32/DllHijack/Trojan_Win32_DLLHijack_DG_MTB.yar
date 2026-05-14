
rule Trojan_Win32_DLLHijack_DG_MTB{
	meta:
		description = "Trojan:Win32/DLLHijack.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {47 55 50 2e 45 58 45 20 4c 49 42 43 55 52 4c 2e 44 4c 4c 20 50 52 4f 58 59 20 2d 20 50 41 59 4c 4f 41 44 20 54 48 52 45 41 44 } //1 GUP.EXE LIBCURL.DLL PROXY - PAYLOAD THREAD
		$a_81_1 = {44 4c 4c 5f 50 52 4f 43 45 53 53 5f 41 54 54 41 43 48 20 28 47 55 50 2e 65 78 65 20 2b 20 73 68 61 64 6f 77 70 69 70 65 2e 6e 65 74 77 6f 72 6b 3a 38 34 34 33 29 } //1 DLL_PROCESS_ATTACH (GUP.exe + shadowpipe.network:8443)
		$a_81_2 = {44 4c 4c 2d 53 69 64 65 6c 6f 61 64 69 6e 67 } //1 DLL-Sideloading
		$a_81_3 = {52 45 4d 4f 54 45 20 49 4e 4a 45 43 54 49 4f 4e } //1 REMOTE INJECTION
		$a_81_4 = {53 48 45 4c 4c 43 4f 44 45 20 44 4f 57 4e 4c 4f 41 44 } //1 SHELLCODE DOWNLOAD
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}