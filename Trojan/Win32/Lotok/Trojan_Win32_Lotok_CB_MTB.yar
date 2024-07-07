
rule Trojan_Win32_Lotok_CB_MTB{
	meta:
		description = "Trojan:Win32/Lotok.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 08 02 ca 32 ca 02 ca 32 ca 88 08 40 4e 75 da } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //2 VirtualAlloc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}