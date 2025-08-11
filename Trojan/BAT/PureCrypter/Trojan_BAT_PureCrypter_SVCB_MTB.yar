
rule Trojan_BAT_PureCrypter_SVCB_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.SVCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 5a 00 00 00 11 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 13 03 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a c3 ff ff ff 26 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}