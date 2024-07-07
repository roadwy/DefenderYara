
rule Trojan_Win32_ProcessHijack_PA_MTB{
	meta:
		description = "Trojan:Win32/ProcessHijack.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 be f9 ff ff f7 d1 e8 00 00 00 00 5b 83 c3 11 93 ba 8f 3f 5d 1a 31 10 83 c0 04 e2 f9 } //1
		$a_01_1 = {b9 41 06 00 00 e8 00 00 00 00 5b 83 c3 10 93 81 30 6b af 89 1d 83 c0 04 e2 f5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}