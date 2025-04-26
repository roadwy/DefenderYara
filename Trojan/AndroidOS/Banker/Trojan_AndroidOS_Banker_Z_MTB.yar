
rule Trojan_AndroidOS_Banker_Z_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.Z!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 72 df 5c 71 10 23 cb 02 00 0c 02 54 75 df 5c 71 10 26 cb 05 00 0c 05 70 40 1e cb 27 05 0a 02 32 02 22 00 22 05 15 1b 1a 06 8c 0b 70 20 10 a9 65 00 6e 20 16 a9 25 00 6e 10 29 a9 05 00 0c 05 71 20 69 c5 51 00 3b 02 0f 00 5c 74 de 5c 54 75 df 5c 1a 06 8b 0b 71 20 ae 0e 26 00 0c 02 71 20 2b cb 25 00 } //1
		$a_01_1 = {22 00 15 1b 1a 01 51 0a 70 20 10 a9 10 00 60 01 fd 2e 6e 20 16 a9 10 00 1a 01 fb 04 6e 20 1b a9 10 00 62 01 fc 2e 6e 20 1b a9 10 00 1a 01 e6 04 6e 20 1b a9 10 00 62 01 ff 2e 6e 20 1b a9 10 00 1a 01 ec 04 6e 20 1b a9 10 00 62 01 02 2f 6e 20 1b a9 10 00 1a 01 f3 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}