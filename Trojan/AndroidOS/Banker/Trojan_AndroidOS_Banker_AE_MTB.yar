
rule Trojan_AndroidOS_Banker_AE_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.AE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 20 61 21 24 00 0c 05 1f 05 d3 01 d8 09 02 64 6e 20 49 08 35 00 0c 0a 72 5a b1 0b 6f 96 0c 09 22 0a c7 01 70 10 1e 08 0a 00 6e 20 2d 08 7a 00 0c 0a 6e 20 30 08 8a 00 0c 0a 20 1b 57 02 38 0b 10 00 6e 10 67 10 01 00 0a 0b 38 0b 0a 00 6e 10 c6 0c 01 00 0a 0b 38 0b 04 00 01 0b 28 02 } //1
		$a_01_1 = {b1 64 6e 10 8a 0c 0a 00 0a 03 71 10 49 06 0a 00 0a 06 38 06 11 00 6e 10 8d 0c 0a 00 0a 06 6e 10 88 0c 0a 00 0a 07 b0 67 b1 75 6e 10 88 0c 0a 00 0a 06 b1 60 b1 43 82 33 82 00 6e 30 cb 08 3b 00 82 40 12 03 15 06 34 43 6e 40 c6 08 6b 30 6e 30 99 0f 41 05 6e 20 91 0f b1 00 0a 00 38 00 05 00 6e 10 07 0d 0a 00 6e 20 c4 08 2b 00 0e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}