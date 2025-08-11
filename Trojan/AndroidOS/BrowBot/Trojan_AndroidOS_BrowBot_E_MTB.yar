
rule Trojan_AndroidOS_BrowBot_E_MTB{
	meta:
		description = "Trojan:AndroidOS/BrowBot.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 01 18 01 6e 20 e2 1f 10 00 54 31 27 02 6e 20 e2 1f 10 00 1a 01 ac 00 6e 20 e2 1f 10 00 6e 10 12 0a 03 00 0a 01 71 10 58 1f 01 00 0c 01 24 10 ba 0f 01 00 0c 01 1a 02 7d 03 71 20 b5 1f 12 00 0c 01 6e 20 e2 1f 10 00 } //1
		$a_01_1 = {15 0a 00 ff 6e 20 fe 02 a3 00 22 0a 88 00 62 04 ed 00 70 40 42 02 9a 44 22 04 97 00 70 10 cb 02 04 00 6e 10 39 02 09 00 0a 07 b1 07 7b 77 82 77 15 08 00 40 c9 87 6e 10 38 02 09 00 0a 09 b1 09 7b 99 82 99 c9 89 6e 30 d4 02 74 09 6e 20 72 03 4a 00 6e 20 06 03 a3 00 6e 53 64 02 52 65 12 09 6e 20 ae 02 92 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}