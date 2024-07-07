
rule Trojan_Win32_DarkGateLoader_EB_MTB{
	meta:
		description = "Trojan:Win32/DarkGateLoader.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {44 4c 4c 5f 4c 6f 61 64 65 72 55 } //1 DLL_LoaderU
		$a_01_1 = {53 74 6f 72 61 67 65 20 6e 6f 74 20 65 78 69 73 74 73 } //1 Storage not exists
		$a_01_2 = {63 6f 72 72 75 70 74 65 64 20 64 61 74 61 20 32 } //1 corrupted data 2
		$a_01_3 = {73 63 72 69 70 74 2e 61 75 33 } //1 script.au3
		$a_01_4 = {41 75 74 6f 69 74 33 2e 65 78 65 } //1 Autoit3.exe
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}