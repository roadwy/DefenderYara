
rule Trojan_BAT_Lazy_AMBC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 17 9a 28 ?? 00 00 0a 7e ?? ?? 00 04 18 9a 28 ?? 00 00 0a 6f ?? ?? 00 0a 13 01 38 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}