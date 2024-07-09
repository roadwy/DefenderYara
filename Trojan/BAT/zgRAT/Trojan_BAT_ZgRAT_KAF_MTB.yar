
rule Trojan_BAT_ZgRAT_KAF_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 1f 30 28 ?? 00 00 2b 28 ?? 00 00 2b 13 03 38 ?? 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}