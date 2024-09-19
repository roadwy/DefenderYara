
rule Trojan_Linux_CoinMiner_AX_MTB{
	meta:
		description = "Trojan:Linux/CoinMiner.AX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8b 0d f9 0c 20 00 45 85 c9 75 ?? 45 31 d2 48 63 d2 48 63 ff b8 3d 00 00 00 0f 05 48 3d 00 f0 ff ff 77 ?? c3 48 c7 c2 fc ff ff ff f7 d8 64 89 02 48 83 c8 ff c3 53 } //1
		$a_03_1 = {64 48 c7 04 25 30 06 00 00 ff ff ff ff f0 64 83 0c 25 08 03 00 00 10 64 48 8b 3c 25 00 03 00 00 e8 bb f4 bf ff f4 66 2e 0f 1f 84 00 00 00 00 00 f7 c7 02 00 00 00 75 ?? 64 8b 04 25 08 03 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}