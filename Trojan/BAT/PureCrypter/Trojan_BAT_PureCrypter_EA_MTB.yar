
rule Trojan_BAT_PureCrypter_EA_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 04 7e 09 00 00 04 7b 02 00 00 04 6f 1e 00 00 0a a2 11 04 17 58 13 04 11 04 08 8e 69 32 e0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}