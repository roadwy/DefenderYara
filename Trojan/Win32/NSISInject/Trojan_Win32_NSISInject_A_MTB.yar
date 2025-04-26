
rule Trojan_Win32_NSISInject_A_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 6c 61 6e 63 2d 53 61 62 6c 6f 6e } //2 Blanc-Sablon
		$a_01_1 = {48 65 69 74 69 6b 69 42 75 72 6c 48 61 6e 64 6c 65 62 61 72 4b 6f 68 6c 72 61 62 69 } //2 HeitikiBurlHandlebarKohlrabi
		$a_01_2 = {67 61 79 61 6c 73 } //2 gayals
		$a_01_3 = {53 68 6f 67 75 6e 53 75 62 6d 6f 6c 65 63 75 6c 65 } //2 ShogunSubmolecule
		$a_01_4 = {42 65 6e 6a 79 3a 3a 53 68 61 77 6d } //2 Benjy::Shawm
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}