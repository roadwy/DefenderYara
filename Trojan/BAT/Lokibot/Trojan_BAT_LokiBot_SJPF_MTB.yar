
rule Trojan_BAT_LokiBot_SJPF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SJPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 05 11 06 6f ?? ?? ?? 0a 13 07 08 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 12 07 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 08 20 ?? ?? ?? 00 28 ?? ?? ?? 06 00 08 6f ?? ?? ?? 0a 00 00 11 06 17 58 13 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}