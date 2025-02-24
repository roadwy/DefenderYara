
rule Trojan_BAT_QQPass_NIT_MTB{
	meta:
		description = "Trojan:BAT/QQPass.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 18 02 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 1d 2b 45 11 1d 6f ?? 00 00 0a 74 1a 00 00 01 13 1e 00 72 64 05 00 70 13 1f 11 1e 6f ?? 00 00 0a 1b 6f ?? 00 00 0a 6f ?? 00 00 0a 13 20 02 73 2c 00 00 0a 28 ?? 00 00 06 00 02 28 ?? 00 00 06 11 20 6f ?? 00 00 0a 00 00 11 1d 6f ?? 00 00 0a 2d b2 de 16 } //2
		$a_01_1 = {54 55 4b 53 79 73 74 65 6d 46 6f 72 53 65 6c 6c } //1 TUKSystemForSell
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_QQPass_NIT_MTB_2{
	meta:
		description = "Trojan:BAT/QQPass.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 e1 02 00 70 13 18 02 28 ?? 00 00 06 11 13 11 15 20 00 04 00 00 12 17 28 ?? 00 00 06 26 72 19 03 00 70 13 19 28 ?? 00 00 0a 11 15 6f ?? 00 00 0a 6f ?? 00 00 0a 13 1a 72 49 03 00 70 13 1b 00 11 1a 02 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 1d 2b 38 11 1d 6f ?? 00 00 0a 74 16 00 00 01 13 1e 00 72 87 03 00 70 13 1f 02 11 1e 6f ?? 00 00 0a 1f 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 00 72 af 03 00 70 13 20 00 11 1d 6f ?? 00 00 0a 2d bf de 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}