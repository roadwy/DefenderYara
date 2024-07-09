
rule Trojan_BAT_CoinMiner_NCI_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 26 00 00 0a 0c 06 28 ?? 00 00 06 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 09 11 04 28 ?? 00 00 06 08 6f ?? 00 00 0a 26 } //5
		$a_01_1 = {55 6c 74 72 61 49 53 4f } //1 UltraISO
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_CoinMiner_NCI_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.NCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 e0 13 05 16 13 06 1f 18 58 11 04 58 13 07 20 ?? ?? ?? a8 13 08 11 17 20 ?? ?? ?? 65 5a 20 ?? ?? ?? f8 61 38 ?? ?? ?? ff 20 ?? ?? ?? 97 13 0a 11 17 20 ?? ?? ?? 50 5a 20 ?? ?? ?? a8 61 38 ?? ?? ?? ff } //5
		$a_01_1 = {57 69 6e 4d 65 64 69 61 2e 57 69 6e 4d 65 64 69 61 5f } //1 WinMedia.WinMedia_
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}