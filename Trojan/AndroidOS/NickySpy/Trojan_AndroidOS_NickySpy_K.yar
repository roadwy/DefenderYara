
rule Trojan_AndroidOS_NickySpy_K{
	meta:
		description = "Trojan:AndroidOS/NickySpy.K,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 6e 76 69 72 52 65 63 6f 72 64 53 65 72 76 69 63 65 } //2 EnvirRecordService
		$a_01_1 = {6e 69 63 6b 79 2f 6c 79 79 77 73 2f 61 73 6c 2f 53 4c 69 73 74 65 6e 65 72 } //2 nicky/lyyws/asl/SListener
		$a_01_2 = {6e 6f 77 73 6d 73 64 61 74 65 } //2 nowsmsdate
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}