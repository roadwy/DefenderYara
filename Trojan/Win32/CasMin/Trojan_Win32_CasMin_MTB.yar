
rule Trojan_Win32_CasMin_MTB{
	meta:
		description = "Trojan:Win32/CasMin!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 69 62 67 63 6a 2d 31 33 2e 64 6c 6c } //1 libgcj-13.dll
		$a_01_1 = {5f 4a 76 5f 52 65 67 69 73 74 65 72 43 6c 61 73 73 65 73 } //1 _Jv_RegisterClasses
		$a_01_2 = {25 25 67 6c 75 65 3a 4c } //1 %%glue:L
		$a_01_3 = {62 69 74 33 32 } //1 bit32
		$a_01_4 = {73 72 6c 75 61 } //1 srlua
		$a_01_5 = {74 6d 70 6e 61 6d } //1 tmpnam
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}