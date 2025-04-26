
rule Trojan_BAT_ModernLoader_A_MTB{
	meta:
		description = "Trojan:BAT/ModernLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 d5 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 3a 00 00 00 10 00 00 00 30 00 00 00 54 } //2
		$a_01_1 = {73 65 74 5f 57 69 6e 64 6f 77 53 74 79 6c 65 } //1 set_WindowStyle
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}