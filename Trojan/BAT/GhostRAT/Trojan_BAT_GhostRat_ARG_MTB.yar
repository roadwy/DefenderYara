
rule Trojan_BAT_GhostRat_ARG_MTB{
	meta:
		description = "Trojan:BAT/GhostRat.ARG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 06 16 13 07 2b 14 11 06 11 07 11 05 11 07 91 1f 7f 5f d1 9d 11 07 17 58 13 07 11 07 11 04 32 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}