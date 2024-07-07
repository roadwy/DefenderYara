
rule Trojan_Win64_Shelm_MD_MTB{
	meta:
		description = "Trojan:Win64/Shelm.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {6c 73 7a 74 6a 75 77 6c 6a 6b 6a 6e 76 79 6a 72 6f 71 65 71 73 79 71 64 64 73 74 72 62 72 75 65 } //5 lsztjuwljkjnvyjroqeqsyqddstrbrue
		$a_01_1 = {6a 6e 6e 66 63 6f 79 2e 63 70 6c } //2 jnnfcoy.cpl
		$a_01_2 = {4e 69 6d 4d 61 69 6e } //2 NimMain
		$a_01_3 = {44 6c 6c 49 6e 73 74 61 6c 6c } //1 DllInstall
		$a_01_4 = {44 6c 6c 4d 61 69 6e } //1 DllMain
		$a_01_5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_6 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=13
 
}