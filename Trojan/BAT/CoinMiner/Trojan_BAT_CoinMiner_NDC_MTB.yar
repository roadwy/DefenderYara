
rule Trojan_BAT_CoinMiner_NDC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 7c 00 00 04 28 ?? 00 00 0a 0a 06 2c 0d 00 7e ?? 00 00 04 28 ?? 00 00 0a 00 00 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 0a 00 02 16 28 ?? 00 00 0a 00 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a } //5
		$a_01_1 = {4d 00 53 00 34 00 31 00 20 00 45 00 43 00 55 00 20 00 50 00 6f 00 72 00 74 00 61 00 6c 00 } //1 MS41 ECU Portal
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}