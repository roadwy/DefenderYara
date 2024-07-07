
rule Trojan_BAT_CoinMiner_PSNC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PSNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {d0 01 00 00 02 28 14 00 00 0a 6f 18 00 00 0a 25 6f 0e 00 00 0a 0a 06 6f 37 00 00 0a 16 31 0d 06 16 6f 0f 00 00 0a 1f 3c fe 01 2b 01 16 0b 28 19 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}