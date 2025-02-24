
rule Trojan_Win32_DarkGate_GB_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 d2 f7 f3 } //1
		$a_02_1 = {30 04 0f 41 89 c8 81 f9 [0-04] 76 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}