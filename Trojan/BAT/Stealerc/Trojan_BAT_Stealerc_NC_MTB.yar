
rule Trojan_BAT_Stealerc_NC_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 1c 13 01 12 01 1d 13 03 12 03 6f ?? 00 00 06 26 } //3
		$a_03_1 = {02 8e 69 1f 11 da 17 d6 8d ?? 00 00 01 13 0b 20 ?? 00 00 00 28 ?? 00 00 06 3a } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
rule Trojan_BAT_Stealerc_NC_MTB_2{
	meta:
		description = "Trojan:BAT/Stealerc.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 d2 52 07 08 8f ?? 00 00 01 25 47 07 11 05 91 06 1a 58 4a 61 d2 61 d2 52 07 11 05 8f 07 00 00 01 25 47 07 08 91 61 d2 52 11 05 17 58 } //5
		$a_01_1 = {42 69 6e 61 6e 63 65 20 41 69 72 64 72 6f 70 5f 2e 65 78 65 } //1 Binance Airdrop_.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}