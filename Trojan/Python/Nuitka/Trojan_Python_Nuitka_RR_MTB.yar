
rule Trojan_Python_Nuitka_RR_MTB{
	meta:
		description = "Trojan:Python/Nuitka.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c9 c1 e8 08 33 04 8a 89 c1 41 32 41 0a 0f b6 c0 c1 e9 08 33 0c 82 89 c8 41 32 49 0b 0f b6 c9 c1 e8 08 33 04 8a } //1
		$a_01_1 = {75 71 6d 61 6b 65 2e 65 78 65 } //1 uqmake.exe
		$a_01_2 = {4c 61 7a 79 4c 6f 61 64 65 72 2e 65 78 65 63 5f 6d 6f 64 75 6c 65 } //1 LazyLoader.exec_module
		$a_01_3 = {61 4e 55 49 54 4b 41 5f 50 41 43 4b 41 47 45 5f 73 68 69 62 6f 6b 65 6e 36 } //1 aNUITKA_PACKAGE_shiboken6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}