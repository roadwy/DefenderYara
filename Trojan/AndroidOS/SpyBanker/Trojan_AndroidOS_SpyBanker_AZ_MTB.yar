
rule Trojan_AndroidOS_SpyBanker_AZ_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.AZ!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6e 10 39 0d 05 00 0c 00 1a 01 12 e3 71 20 41 fe 10 00 20 01 3a 00 38 01 cc 00 1f 00 3a 00 22 01 c9 22 70 10 41 e8 01 00 1a 03 e3 6d 6e 20 4c e8 31 00 0c 01 62 03 b1 84 6e 10 6c e6 03 00 0c 03 6e 20 4c e8 31 00 0c 01 6e 20 4c e8 21 00 0c 01 6e 10 38 0d 05 00 0c 02 6e 20 4b e8 21 00 0c 01 13 02 0a 00 6e 20 44 e8 21 00 0c 01 6e 10 52 e8 01 00 0c 01 22 02 c9 22 } //2
		$a_00_1 = {64 65 76 69 6c 2f 73 6b 2f 4d 61 69 6e 53 65 72 76 69 63 65 } //1 devil/sk/MainService
		$a_00_2 = {63 6f 6d 2f 62 61 6e 6b 69 6e 67 73 65 63 75 72 69 74 79 69 6e 63 2f 63 75 73 74 6f 6d 65 72 73 } //1 com/bankingsecurityinc/customers
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}