
rule Trojan_AndroidOS_Hqwar_K_MTB{
	meta:
		description = "Trojan:AndroidOS/Hqwar.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6d 65 6d 2f 69 6e 73 74 61 6c 6c 64 72 6f 70 73 65 73 73 69 6f 6e } //1 com/mem/installdropsession
		$a_01_1 = {1a 01 05 14 16 02 00 00 16 04 ff ff 07 80 74 06 ac 02 00 00 0c 08 6e 10 87 16 06 00 0c 00 6e 20 bc 02 70 00 0c 07 15 00 60 00 23 00 10 07 6e 20 f9 20 07 00 0a 01 3a 01 07 00 12 02 6e 40 ff 20 08 12 28 f6 38 07 05 00 6e 10 f8 20 07 00 38 08 05 00 6e 10 fe 20 08 00 0e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}