
rule Backdoor_AndroidOS_Ztorg_B_MTB{
	meta:
		description = "Backdoor:AndroidOS/Ztorg.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {10 40 2d e9 3c 10 9f e5 08 d0 4d e2 14 30 8d e2 01 10 9f e7 a8 40 81 e2 03 20 a0 e1 10 10 9d e5 04 00 a0 e1 04 30 8d e5 81 94 00 eb 04 10 a0 e1 0a 00 a0 e3 81 94 00 eb 08 d0 8d e2 10 40 bd e8 10 d0 8d e2 } //1
		$a_00_1 = {1c 68 3e 4b 79 44 20 1c eb 58 1b 68 05 93 3c 4b eb 58 1b 68 06 93 3b 4b eb 58 1b 68 07 93 3a 4b eb 58 1f 68 ff f7 8f fe 38 4a 39 4b 06 1c 31 1c 7b 44 7a 44 20 1c ff f7 b1 fe 31 1c 02 1c 20 1c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}