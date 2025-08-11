
rule Trojan_AndroidOS_Crocodilus_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Crocodilus.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 01 00 00 52 02 0d 01 62 03 17 01 62 04 1c 07 12 15 12 36 12 07 12 08 12 29 38 02 51 00 32 52 36 00 32 92 21 00 33 62 17 00 52 02 0c 01 52 0a 0b 01 54 0b 0a 01 54 0c 09 01 54 0d 0e 01 1f 0d 7d 04 77 01 e1 02 15 00 01 87 01 28 07 b2 07 db } //1
		$a_01_1 = {35 ae 1f 00 22 0d b8 00 54 08 0f 01 13 12 00 00 08 15 0d 00 02 13 0e 00 07 8e 07 f8 02 0f 13 00 08 10 08 00 08 11 0c 00 76 06 10 02 0d 00 71 40 5e 01 72 6d d8 0e 13 01 07 8f 12 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}