
rule Trojan_BAT_ClipBanker_KA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 46 12 04 28 ?? 00 00 0a 13 05 11 05 06 28 ?? 00 00 06 13 06 11 06 08 32 2e 11 06 08 33 0b 07 11 05 6f ?? 00 00 0a 26 2b 1e 11 06 08 31 19 } //5
		$a_01_1 = {31 45 4e 39 44 6d 73 6e 52 6b 39 47 4c 61 74 58 70 37 76 32 57 71 55 6e 6d 42 36 58 7a 6e 44 64 67 76 } //5 1EN9DmsnRk9GLatXp7v2WqUnmB6XznDdgv
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}