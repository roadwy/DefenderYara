
rule Trojan_Win64_Rozena_PAFW_MTB{
	meta:
		description = "Trojan:Win64/Rozena.PAFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 03 48 8b 43 08 4c 29 c0 48 39 c1 73 ?? 4c 8b 0e 4c 8b 56 08 4d 29 ca 48 89 c8 31 d2 49 f7 f2 41 8a 04 11 41 32 04 08 48 8b 17 88 04 0a 48 ff c1 eb } //2
		$a_01_1 = {44 65 63 72 79 70 74 65 64 20 73 68 65 6c 6c 63 6f 64 65 } //2 Decrypted shellcode
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}