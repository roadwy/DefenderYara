
rule Trojan_BAT_DuckTail_ADT_MTB{
	meta:
		description = "Trojan:BAT/DuckTail.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 0a 17 7e ?? 00 00 04 6f ?? ?? ?? 06 12 00 73 ?? 00 00 0a 0b 06 2d 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}