
rule Trojan_BAT_ZgRAT_KAG_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 04 73 ?? 00 00 0a 11 03 11 01 28 ?? 00 00 2b 28 ?? 00 00 2b 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}