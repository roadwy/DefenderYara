
rule Trojan_BAT_AsyncRAT_MBEQ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 2c 5d 06 06 72 3f 08 00 70 6f 90 01 01 00 00 0a 72 3f 08 00 70 28 90 01 01 00 00 0a 58 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 08 11 07 11 08 16 11 08 8e 69 6f 90 01 01 00 00 0a 11 07 90 00 } //1
		$a_01_1 = {50 61 74 72 69 63 6b 5f 43 72 79 70 74 65 72 5f 53 74 75 62 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 } //1 Patrick_Crypter_Stub.Form1.resou
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}