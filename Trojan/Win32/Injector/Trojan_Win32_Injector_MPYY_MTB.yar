
rule Trojan_Win32_Injector_MPYY_MTB{
	meta:
		description = "Trojan:Win32/Injector.MPYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 00 35 35 33 19 e9 e7 09 bd f0 54 4d 97 c4 03 7c ee } //1
		$a_01_1 = {32 f0 23 2e 1c 27 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}