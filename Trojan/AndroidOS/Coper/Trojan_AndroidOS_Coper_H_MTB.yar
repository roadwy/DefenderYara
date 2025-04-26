
rule Trojan_AndroidOS_Coper_H_MTB{
	meta:
		description = "Trojan:AndroidOS/Coper.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 08 f6 01 70 10 4b 09 08 00 1a 0a 08 04 6e 20 56 09 a8 00 6e 20 51 09 98 00 1a 09 48 00 6e 20 56 09 98 00 6e 10 5b 09 08 00 0c 08 22 09 d7 01 70 20 cb 08 89 00 27 09 } //1
		$a_01_1 = {72 10 6b 0a 0c 00 0a 02 38 02 42 00 72 10 6c 0a 0c 00 0c 02 1f 02 53 02 72 10 82 0a 02 00 0c 03 1f 03 db 01 6e 10 d4 08 03 00 0a 03 72 10 83 0a 02 00 0c 02 1f 02 db 01 6e 10 d4 08 02 00 0a 02 12 14 12 05 01 46 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}