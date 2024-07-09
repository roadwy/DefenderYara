
rule Trojan_Linux_CoinMiner_C_xp{
	meta:
		description = "Trojan:Linux/CoinMiner.C!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 31 ed 48 89 e7 48 8d 35 f4 e9 bf ff 48 83 e4 f0 e8 ?? ?? ?? 00 48 8d 57 08 50 48 8b 37 4c 8d 05 5e b9 0c 00 48 8b 0d dd 38 44 00 45 31 c9 48 8d 3d 7b f6 ff ff } //1
		$a_00_1 = {48 8d 3d c7 45 44 00 48 8d 05 c7 45 44 00 55 48 29 f8 48 89 e5 48 83 f8 0e 76 0f 48 8b 05 9c 38 44 00 48 85 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}