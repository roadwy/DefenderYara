
rule Backdoor_Linux_Mirai_JF_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JF!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 2b 63 64 1f 8d a3 65 25 d2 b3 64 0b 42 b3 63 a7 00 1a 01 0b 42 18 33 e1 51 03 6b 20 d0 63 64 17 03 0b 40 1a 02 a7 00 03 67 1a 01 d7 03 1c d3 18 36 6c 32 23 64 0b 43 1a 06 a7 00 7c 36 0c 36 1a 01 0c a0 18 32 } //1
		$a_01_1 = {0c 91 10 34 00 8b 5f 65 53 61 00 41 1a 31 53 60 e3 6f f6 6e 0b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}