
rule Trojan_Win32_CryptInject_PAGB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PAGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //2 ReflectiveLoader
		$a_01_1 = {69 6e 6a 65 63 74 69 6f 6e 2e 64 6c 6c } //2 injection.dll
		$a_01_2 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //2 SeDebugPrivilege
		$a_01_3 = {46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 74 68 65 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 } //1 Failed to open the target process
		$a_01_4 = {5b 2b 5d 20 49 6e 6a 65 63 74 65 64 20 74 68 65 20 44 4c 4c 20 69 6e 74 6f 20 70 72 6f 63 65 73 73 20 25 6c 75 } //1 [+] Injected the DLL into process %lu
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}