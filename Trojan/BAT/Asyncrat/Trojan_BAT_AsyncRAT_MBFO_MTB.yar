
rule Trojan_BAT_AsyncRAT_MBFO_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 06 06 6f ?? 01 00 0a 25 26 1f 10 6a 59 17 6a 58 d4 8d 19 00 00 01 13 07 11 06 11 07 16 11 07 8e 69 } //1
		$a_03_1 = {de 00 20 88 13 00 00 28 ?? 00 00 0a 2b d3 } //1
		$a_01_2 = {41 73 79 6e 63 43 6c 69 65 6e 74 00 41 73 79 6e 63 43 6c 69 65 6e 74 2e 65 78 65 } //1
		$a_01_3 = {43 4f 5f 56 65 72 69 66 79 48 61 73 68 } //1 CO_VerifyHash
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}