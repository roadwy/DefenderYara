
rule Trojan_AndroidOS_EvilInst_E_MTB{
	meta:
		description = "Trojan:AndroidOS/EvilInst.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 01 30 0e 70 10 a1 15 00 00 0e 00 } //1
		$a_01_1 = {22 00 5e 03 12 01 70 30 24 15 20 01 12 01 23 11 fc 03 6e 20 2d 0d 10 00 0e 00 } //1
		$a_01_2 = {67 67 74 6c 61 6e 2f 73 75 62 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 ggtlan/sub/MainActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}