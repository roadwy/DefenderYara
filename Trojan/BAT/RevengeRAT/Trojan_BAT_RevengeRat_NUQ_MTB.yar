
rule Trojan_BAT_RevengeRat_NUQ_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.NUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 03 11 05 91 06 61 09 08 91 61 b4 9c 08 04 6f ?? ?? ?? 0a 17 da } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}