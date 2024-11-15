
rule Trojan_BAT_PureCrypter_APC_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.APC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 1a 06 08 02 08 91 07 08 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}