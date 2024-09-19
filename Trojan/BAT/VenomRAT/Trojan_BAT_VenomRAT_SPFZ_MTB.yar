
rule Trojan_BAT_VenomRAT_SPFZ_MTB{
	meta:
		description = "Trojan:BAT/VenomRAT.SPFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d2 13 32 11 18 1e 63 d1 13 18 11 16 11 0a 91 13 2a 11 16 11 0a 11 25 11 2a 61 19 11 1c 58 61 11 32 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}