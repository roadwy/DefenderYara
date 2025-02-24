
rule Trojan_BAT_AsyncRAT_SPY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 73 09 00 00 0a 0c 08 07 17 73 0a 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 04 de 1e 09 2c 06 09 6f ?? 00 00 0a dc } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}