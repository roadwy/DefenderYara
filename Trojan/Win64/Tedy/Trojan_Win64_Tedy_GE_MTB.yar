
rule Trojan_Win64_Tedy_GE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c1 32 02 32 44 0d ff 34 82 88 44 0d ff 48 ff c1 48 83 f9 0e 72 e8 } //1
		$a_01_1 = {44 6c 6c 49 6e 73 74 61 6c 6c } //1 DllInstall
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}