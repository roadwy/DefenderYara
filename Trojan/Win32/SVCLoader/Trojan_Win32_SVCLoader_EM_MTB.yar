
rule Trojan_Win32_SVCLoader_EM_MTB{
	meta:
		description = "Trojan:Win32/SVCLoader.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {79 65 46 6a 46 53 69 66 71 36 38 79 35 44 56 78 76 68 6b 35 74 5a 47 49 34 7a 51 5a 66 38 7a 35 65 } //1 yeFjFSifq68y5DVxvhk5tZGI4zQZf8z5e
		$a_01_1 = {41 54 35 44 78 56 6c 64 75 } //1 AT5DxVldu
		$a_01_2 = {44 57 72 47 6d 53 4f } //1 DWrGmSO
		$a_01_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}