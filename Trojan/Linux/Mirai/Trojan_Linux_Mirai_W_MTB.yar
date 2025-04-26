
rule Trojan_Linux_Mirai_W_MTB{
	meta:
		description = "Trojan:Linux/Mirai.W!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {f4 13 02 b0 61 6a f4 1b c0 b0 60 8a f0 13 02 b0 40 22 44 00 f0 1b 00 b1 40 8a 50 73 05 f2 } //1
		$a_00_1 = {f8 13 02 b0 ab e2 0a f4 e4 13 02 b0 61 6a e4 1b c0 b0 40 8a f8 1b 80 b0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}