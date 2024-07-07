
rule Trojan_BAT_SilentCryptoMiner_rootkit{
	meta:
		description = "Trojan:BAT/SilentCryptoMiner!rootkit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 0b 11 0a 11 06 28 10 00 00 06 26 11 0a 11 06 07 6a 20 00 30 00 00 1f 40 28 0e 00 00 06 26 11 0a 11 06 02 08 16 6a 28 0f 00 00 06 26 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}