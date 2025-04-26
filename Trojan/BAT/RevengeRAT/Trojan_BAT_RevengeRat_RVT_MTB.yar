
rule Trojan_BAT_RevengeRat_RVT_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.RVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d6 03 8e 69 11 04 16 9a 6f ?? ?? ?? 0a 04 6f ?? ?? ?? 0a d6 da 6f ?? ?? ?? 0a 00 07 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}