
rule Backdoor_Linux_Mirai_HC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.HC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c d7 0b e6 0c d5 72 61 52 63 13 62 6d 42 0b d6 1a 22 33 60 62 61 12 27 09 d7 ed e1 1d 40 3a 20 72 61 2a 20 32 27 19 42 12 26 2a 20 02 25 } //1
		$a_01_1 = {86 2f 00 e1 96 2f 00 e2 a6 2f 43 6a b6 2f 22 4f 41 50 f0 7f 12 1f 23 1f ff 88 12 2f 21 1f 04 8d f3 6b 03 64 1d d0 0b 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}