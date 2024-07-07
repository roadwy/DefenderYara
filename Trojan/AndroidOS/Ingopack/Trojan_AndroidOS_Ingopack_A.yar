
rule Trojan_AndroidOS_Ingopack_A{
	meta:
		description = "Trojan:AndroidOS/Ingopack.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 61 63 68 42 61 73 65 43 6f 6e 74 65 78 74 74 } //1 attachBaseContextt
		$a_00_1 = {4c 61 2f 61 2f 45 6e 63 72 79 70 74 6f 72 } //1 La/a/Encryptor
		$a_02_2 = {12 02 08 00 16 00 71 20 65 00 20 00 0c 01 1a 04 90 01 08 0c 03 1a 04 90 01 06 04 00 0c 05 1a 04 90 01 02 71 10 90 01 02 04 00 0c 06 1a 04 90 01 02 71 10 90 01 02 04 00 0c 07 12 12 23 28 90 01 01 01 12 02 1c 09 90 01 01 01 4d 09 08 02 6e 20 90 01 02 83 00 0c 0a 12 12 23 2b 90 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2) >=4
 
}