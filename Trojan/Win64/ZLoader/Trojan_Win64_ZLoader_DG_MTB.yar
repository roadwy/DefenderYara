
rule Trojan_Win64_ZLoader_DG_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_80_0 = {5b 2d 5d 20 52 65 71 75 65 73 74 20 6c 69 6d 69 74 20 72 65 61 63 68 65 64 2e } //[-] Request limit reached.  10
		$a_80_1 = {7b 49 4e 4a 45 43 54 44 41 54 41 7d } //{INJECTDATA}  10
		$a_80_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  1
		$a_80_3 = {4c 64 72 44 6c 6c 2e 64 6c 6c } //LdrDll.dll  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=22
 
}