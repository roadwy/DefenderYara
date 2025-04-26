
rule Trojan_BAT_CoinMiner_BAN_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 05 02 7e ?? 00 00 04 13 0e 7e ?? 0e 00 04 7e ?? 0e 00 04 7e ?? 0e 00 04 61 7e ?? 0e 00 04 40 0d 00 00 00 7e ?? 00 00 04 13 0e 7e ?? 0e 00 04 58 00 02 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a dd } //2
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //1 FlushFinalBlock
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}