
rule Trojan_Win32_CoinMiner_GXT_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.GXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f4 6a 40 68 00 30 00 00 8b 45 dc 8b 48 50 51 8b 55 dc 8b 42 34 50 8b 8d ?? ?? ?? ?? 51 ff 15 } //5
		$a_03_1 = {8b f4 6a 00 8b 45 dc 8b 48 54 51 8b 55 48 52 8b 85 ?? ?? ?? ?? 50 8b 8d ?? ?? ?? ?? 51 ff 15 } //5
		$a_03_2 = {8b f4 8b 85 ?? ?? ?? ?? 50 8b 8d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 8b 85 ?? ?? ?? ?? 50 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=15
 
}