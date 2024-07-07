
rule Trojan_Win32_Graftor_CB_MTB{
	meta:
		description = "Trojan:Win32/Graftor.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b f2 46 8a 02 32 42 01 0f b6 c0 } //1
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}