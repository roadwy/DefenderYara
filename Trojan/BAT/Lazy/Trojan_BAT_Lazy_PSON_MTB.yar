
rule Trojan_BAT_Lazy_PSON_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 7b 15 00 00 04 6f ?? ?? ?? 0a 0a 06 2c 29 00 73 ?? ?? ?? 0a 0b 07 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 02 7b 15 00 00 04 08 6f ?? ?? ?? 0a 00 00 2b 13 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}