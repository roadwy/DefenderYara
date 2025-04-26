
rule Trojan_BAT_Tiny_SPWE_MTB{
	meta:
		description = "Trojan:BAT/Tiny.SPWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 03 00 00 0a 0a 73 04 00 00 0a 13 05 11 05 72 01 00 00 70 6f ?? ?? ?? 0a 11 05 17 6f ?? ?? ?? 0a 11 05 16 6f ?? ?? ?? 0a 11 05 16 6f ?? ?? ?? 0a 11 05 0b 06 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}