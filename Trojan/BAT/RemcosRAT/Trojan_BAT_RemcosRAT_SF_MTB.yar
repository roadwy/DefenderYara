
rule Trojan_BAT_RemcosRAT_SF_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 d1 13 15 11 1d 11 09 91 13 2a 11 1d 11 09 11 2a 11 22 61 11 1f 19 58 61 11 2b 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}