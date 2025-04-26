
rule Trojan_BAT_PureCrypter_ACP_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.ACP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 27 00 00 0a 0c 00 2b 31 16 2b 31 2b 36 2b 3b 00 09 08 6f ?? ?? ?? 0a 00 00 de 11 09 2c 07 09 6f ?? ?? ?? 0a 00 19 2c f6 16 2d f9 dc 16 2d 08 08 6f ?? ?? ?? 0a 13 04 de 33 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}