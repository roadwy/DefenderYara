
rule Trojan_BAT_NjRAT_KAAF_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}