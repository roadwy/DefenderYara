
rule Trojan_BAT_ZgRAT_SG_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {d0 1b 00 00 01 28 12 00 00 06 11 03 72 01 00 00 70 28 13 00 00 06 28 01 00 00 2b 28 14 00 00 06 26 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}