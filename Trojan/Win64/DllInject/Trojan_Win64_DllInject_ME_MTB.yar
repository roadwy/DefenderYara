
rule Trojan_Win64_DllInject_ME_MTB{
	meta:
		description = "Trojan:Win64/DllInject.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 4c 4c 2d 53 69 64 65 6c 6f 61 64 69 6e 67 } //1 DLL-Sideloading
		$a_01_1 = {41 b9 40 00 00 00 41 b8 00 10 00 00 48 8b d6 33 c9 ff d0 4c 8b c6 48 8b d7 48 8b c8 48 8b d8 e8 04 0e 00 00 ff d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}