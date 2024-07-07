
rule Trojan_Win32_DllInject_BM_MTB{
	meta:
		description = "Trojan:Win32/DllInject.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 6e 6a 68 4f 6e 69 68 62 } //2 KnjhOnihb
		$a_01_1 = {4f 62 75 42 76 79 73 } //2 ObuBvys
		$a_01_2 = {4f 6e 6a 69 4d 62 68 75 76 } //2 OnjiMbhuv
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}