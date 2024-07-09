
rule Trojan_BAT_Wagex_SPAP_MTB{
	meta:
		description = "Trojan:BAT/Wagex.SPAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 08 2b 09 2b 0a 2b 0f de 21 06 2b f5 02 2b f4 6f ?? ?? ?? 0a 2b ef 0b 2b ee 16 2d 0c 19 2c 09 06 2c 07 06 6f ?? ?? ?? 0a 00 dc 2b 0b } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}