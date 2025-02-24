
rule Trojan_Win64_Rozena_PAFX_MTB{
	meta:
		description = "Trojan:Win64/Rozena.PAFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 10 4d 8b c8 48 83 c0 08 4c 03 ca 48 f7 d2 49 33 d1 49 23 d3 74 } //2
		$a_01_1 = {44 65 63 72 79 70 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 } //2 Decrypting shellcode
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}