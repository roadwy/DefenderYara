
rule Trojan_BAT_PureCrypter_BAA_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 01 38 1e 00 00 00 11 01 16 ?? ?? 00 00 0a 13 02 38 00 00 00 00 11 00 16 73 15 00 00 0a 13 03 38 11 00 00 00 11 00 11 01 16 1a ?? ?? 00 00 0a 26 38 d1 ff ff ff 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}