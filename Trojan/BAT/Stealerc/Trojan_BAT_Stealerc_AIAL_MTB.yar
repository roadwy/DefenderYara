
rule Trojan_BAT_Stealerc_AIAL_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AIAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f d2 61 d2 81 ?? 00 00 01 16 13 0e 38 ?? ?? ?? ?? 11 06 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}