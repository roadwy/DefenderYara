
rule Trojan_Win64_ReflectiveLoader_RDA_MTB{
	meta:
		description = "Trojan:Win64/ReflectiveLoader.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 65 66 6c 65 63 74 69 76 65 5f 64 6c 6c 2e 78 36 34 2e 64 6c 6c } //2 reflective_dll.x64.dll
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 74 68 65 20 44 4c 4c 20 66 69 6c 65 20 73 69 7a 65 } //1 Failed to get the DLL file size
		$a_01_2 = {5b 2b 5d 20 49 6e 6a 65 63 74 65 64 20 74 68 65 20 27 25 73 27 20 44 4c 4c 20 69 6e 74 6f 20 70 72 6f 63 65 73 73 20 25 64 2e } //1 [+] Injected the '%s' DLL into process %d.
		$a_01_3 = {46 61 69 6c 65 64 20 74 6f 20 69 6e 6a 65 63 74 20 74 68 65 20 44 4c 4c } //1 Failed to inject the DLL
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}