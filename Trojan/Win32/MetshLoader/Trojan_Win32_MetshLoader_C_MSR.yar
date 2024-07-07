
rule Trojan_Win32_MetshLoader_C_MSR{
	meta:
		description = "Trojan:Win32/MetshLoader.C!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 61 6d 69 6c 4d 75 74 65 78 } //1 ShamilMutex
		$a_01_1 = {6d 73 76 63 5f 68 65 6c 6c 6f 77 6f 72 6c 64 2e 64 6c 6c } //1 msvc_helloworld.dll
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 53 68 61 6d 69 6c 5c 52 65 6c 65 61 73 65 5c 53 68 61 6d 69 6c 2e 70 64 62 } //1 C:\Users\admin\source\repos\Shamil\Release\Shamil.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}