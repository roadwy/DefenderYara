
rule Trojan_Win32_Ponystealer_RC_MTB{
	meta:
		description = "Trojan:Win32/Ponystealer.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {9a 20 28 de 16 6e 32 13 01 09 28 4c c8 17 6f 75 19 } //1
		$a_01_1 = {63 00 61 00 6e 00 64 00 69 00 64 00 61 00 20 00 70 00 6f 00 6f 00 66 00 74 00 65 00 72 00 20 00 66 00 6f 00 72 00 65 00 64 00 6f 00 6f 00 6d 00 20 00 62 00 75 00 72 00 62 00 6c 00 65 00 20 00 70 00 72 00 61 00 6e 00 67 00 73 00 20 00 70 00 6c 00 65 00 61 00 64 00 69 00 6e 00 67 00 20 00 67 00 65 00 6e 00 65 00 61 00 6c 00 6f 00 67 00 } //1 candida poofter foredoom burble prangs pleading genealog
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}