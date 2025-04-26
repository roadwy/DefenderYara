
rule Trojan_Linux_Kaiji_D_MTB{
	meta:
		description = "Trojan:Linux/Kaiji.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {10 00 00 06 00 00 00 00 3c 14 00 25 02 9c a0 2d 66 94 e7 10 0c 02 55 f6 00 00 00 00 3c 17 00 28 } //1
		$a_00_1 = {15 80 ff ed 00 00 00 00 ff aa 00 50 ff a1 00 40 ff a9 00 08 ff a8 00 10 ff ab 00 18 0c 00 48 ce 00 00 00 00 93 a1 00 20 14 20 00 0a 00 00 00 00 df a1 00 40 df a3 00 58 df a4 00 38 93 a5 00 2f df a6 00 88 df a7 00 60 df a8 00 70 10 00 ff da } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}