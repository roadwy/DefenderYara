
rule Trojan_Win32_DarkGate_GVE_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.GVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 0f 38 1d e0 66 0f f9 cb 66 0f 69 d0 f7 f3 66 0f 6a ca 66 0f 6c ca } //1
		$a_01_1 = {66 0f fd da 66 0f f9 d1 66 0f 38 1d c1 8a 04 16 66 0f 6d cb 66 0f f9 fd 66 0f 6f cb } //1
		$a_01_2 = {66 0f 62 c2 66 0f 6f d1 66 0f f9 fd 66 0f fd c2 30 04 0f 66 0f fd c2 66 0f 6a ca 66 0f 6a ca } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}