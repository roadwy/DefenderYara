
rule Trojan_Win32_Injector_MRVU_MTB{
	meta:
		description = "Trojan:Win32/Injector.MRVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 4c 64 24 5f e6 e5 a0 c3 e7 94 92 32 8c 56 da 50 d8 e9 } //1
		$a_01_1 = {43 d3 77 aa 4c 81 b3 5b 75 3e a1 17 e7 fa 9a de 7d bb 47 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}