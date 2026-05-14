
rule Trojan_Linux_Mirai_HAE_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 2a 64 3a 20 25 36 34 5b 30 2d 39 41 2d 46 61 2d 66 5d 3a 25 2a 78 20 25 2a 73 20 25 2a 73 20 25 2a 73 20 25 2a 73 20 25 2a 73 20 25 2a 73 20 25 75 [0-80] 2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70 00 00 00 2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70 36 [0-80] 2f 6d 65 64 69 61 00 00 2f 6f 70 74 00 00 00 00 2f 2e 00 00 2e 2f 00 00 28 64 65 6c 65 74 65 64 29 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}