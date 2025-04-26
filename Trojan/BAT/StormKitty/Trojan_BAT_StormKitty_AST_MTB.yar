
rule Trojan_BAT_StormKitty_AST_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.AST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 03 1e 8d ?? 00 00 01 17 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 25 07 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 00 25 07 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 00 0c 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}