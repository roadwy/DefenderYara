
rule Trojan_Win32_Matanbuchus_DA_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 09 00 00 "
		
	strings :
		$a_81_0 = {42 3a 5c 4c 6f 61 64 44 6c 6c 36 5c 4c 6f 61 64 44 6c 6c 5c 72 65 73 75 6c 74 5c 52 65 6c 65 61 73 65 5c 6c 69 62 63 75 72 6c 2e 70 64 62 } //20 B:\LoadDll6\LoadDll\result\Release\libcurl.pdb
		$a_81_1 = {44 6c 6c 49 6e 69 74 69 61 6c 69 7a 65 } //1 DllInitialize
		$a_81_2 = {44 6c 6c 49 6e 73 74 61 6c 6c } //1 DllInstall
		$a_81_3 = {52 65 67 69 73 74 65 72 44 6c 6c } //1 RegisterDll
		$a_81_4 = {54 68 72 65 61 64 46 75 6e 63 74 69 6f 6e } //1 ThreadFunction
		$a_81_5 = {63 75 72 6c 5f 65 61 73 79 5f 63 6c 65 61 6e 75 70 } //1 curl_easy_cleanup
		$a_81_6 = {63 75 72 6c 5f 65 61 73 79 5f 69 6e 69 74 } //1 curl_easy_init
		$a_81_7 = {63 75 72 6c 5f 65 61 73 79 5f 70 65 72 66 6f 72 6d } //1 curl_easy_perform
		$a_81_8 = {63 75 72 6c 5f 65 61 73 79 5f 73 65 74 6f 70 74 } //1 curl_easy_setopt
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=28
 
}