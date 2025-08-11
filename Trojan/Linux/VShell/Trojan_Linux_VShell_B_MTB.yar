
rule Trojan_Linux_VShell_B_MTB{
	meta:
		description = "Trojan:Linux/VShell.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 ff 1b 75 f6 b8 00 00 00 00 b9 01 00 00 00 4c 8d 1d 06 34 78 00 f0 41 0f b1 0b 75 de 48 8b 0d 6c 17 75 00 4c 8d 05 75 41 78 00 4c 8d 0d 0e fa ff ff 48 8b 05 f7 1b 75 00 ff e0 } //1
		$a_01_1 = {48 85 c0 74 24 48 8b 38 48 8b 70 08 31 c0 48 8d 1d d4 f7 44 00 b9 0f 00 00 00 e8 ea 7b fe ff 48 83 c4 28 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}