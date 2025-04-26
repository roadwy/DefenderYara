
rule Trojan_BAT_CoinMiner_NC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 96 04 00 70 80 ?? ?? ?? 04 20 01 00 00 00 16 39 ?? ?? ?? ff 26 38 78 ff ff ff 72 ?? ?? ?? 70 80 01 00 00 04 38 d6 ff ff ff } //5
		$a_01_1 = {6e 69 6d 71 65 46 41 48 38 } //1 nimqeFAH8
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_CoinMiner_NC_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 5e 00 00 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f 56 00 00 0a } //5
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 31 00 37 00 32 00 2e 00 31 00 32 00 38 00 2e 00 31 00 31 00 2f 00 } //1 http://185.172.128.11/
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_CoinMiner_NC_MTB_3{
	meta:
		description = "Trojan:BAT/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 28 00 00 0a 6f ?? ?? 00 0a 13 04 73 ?? ?? 00 0a 13 05 11 05 11 04 28 ?? ?? 00 06 73 ?? ?? 00 0a 13 06 00 11 06 02 28 ?? ?? 00 06 02 8e 69 6f ?? ?? 00 0a 00 11 06 6f ?? ?? 00 0a 00 11 05 6f ?? ?? 00 0a 13 07 de 4e } //5
		$a_03_1 = {28 1b 00 00 0a 0a 73 ?? 00 00 0a 0b 06 02 6f ?? 00 00 0a 0c 08 14 fe 01 13 05 11 05 2d 11 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}
rule Trojan_BAT_CoinMiner_NC_MTB_4{
	meta:
		description = "Trojan:BAT/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {7e 11 00 00 04 28 ?? ?? ?? 0a 0a 25 06 6f ?? ?? ?? 0a 6a 6f ?? ?? ?? 0a 25 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 25 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 73 ?? ?? ?? 0a 25 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 74 ?? ?? ?? 01 6f ?? ?? ?? 0a } //5
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 33 35 35 34 32 35 34 34 37 35 2e 43 31 32 35 35 31 39 38 35 31 33 2e 72 65 73 6f 75 72 63 65 73 } //1 C3554254475.C1255198513.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}