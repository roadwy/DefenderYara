
rule Trojan_BAT_CoinMiner_NCD_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {18 63 d4 8d 27 00 00 01 13 04 11 0e 20 ?? ?? ?? 28 5a 20 cb 8d df 3c 61 38 ?? ?? ?? ff 11 0e 20 60 72 51 6c 5a 20 ?? ?? ?? 18 61 38 c3 fd ff ff 06 8e 69 1a 58 } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 20 57 72 69 74 65 } //1 Windows Write
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}