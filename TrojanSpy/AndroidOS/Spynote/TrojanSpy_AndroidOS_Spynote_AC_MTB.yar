
rule TrojanSpy_AndroidOS_Spynote_AC_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.AC!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 10 3b 00 02 00 22 00 5c 01 12 01 70 30 89 03 20 01 5b 20 6c 05 22 00 5c 01 12 11 70 30 89 03 20 01 5b 20 6d 05 1a 00 cf 0d 5b 20 6e 05 } //1
		$a_01_1 = {22 00 d3 02 70 10 ed 09 00 00 52 31 81 05 6e 20 f4 09 10 00 1a 01 c6 12 6e 20 f8 09 10 00 6e 20 f8 09 40 00 6e 10 fe 09 00 00 0c 04 1a 00 69 07 71 20 25 09 40 00 62 04 31 04 1a 01 d6 01 71 20 26 09 41 00 71 00 39 0e 00 00 1a 04 00 00 71 20 29 09 40 00 0c 01 } //1
		$a_01_2 = {4c 6e 65 74 2f 66 61 6c 63 6f 6e 38 37 38 2f 6d 61 72 6b 65 74 2f 41 64 6d 69 6e 52 65 63 65 69 76 65 72 } //1 Lnet/falcon878/market/AdminReceiver
		$a_01_3 = {4c 6e 65 74 2f 66 61 6c 63 6f 6e 38 37 38 2f 6d 61 72 6b 65 74 2f 73 2f 62 72 6f 64 61 74 7a 2f 53 65 72 76 69 63 65 52 65 73 74 61 72 74 52 65 63 65 69 76 65 72 } //1 Lnet/falcon878/market/s/brodatz/ServiceRestartReceiver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}