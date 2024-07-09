
rule Trojan_BAT_Miner_KA_MTB{
	meta:
		description = "Trojan:BAT/Miner.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 91 0c 07 1e 5d 0d 03 09 9a 13 04 02 07 11 04 08 28 ?? 00 00 06 9c 07 17 d6 0b 07 06 31 e0 } //10
		$a_03_1 = {08 1f 0f 6f ?? 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 ec } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}