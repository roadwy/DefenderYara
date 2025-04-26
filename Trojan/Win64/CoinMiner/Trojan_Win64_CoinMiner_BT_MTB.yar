
rule Trojan_Win64_CoinMiner_BT_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 30 0f be 00 89 44 24 04 48 8b 44 24 30 48 ff c0 48 89 44 24 30 48 8b 44 24 28 0f be 00 33 44 24 04 48 8b 4c 24 28 88 01 48 8b 44 24 28 48 ff c0 48 89 44 24 28 eb } //3
		$a_03_1 = {81 e1 ff 00 00 00 48 63 c9 48 8d 15 ?? ?? ?? 00 33 04 8a b9 04 00 00 00 48 6b c9 03 48 8b 54 24 08 33 04 0a 89 44 24 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}