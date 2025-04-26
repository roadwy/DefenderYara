
rule Trojan_BAT_VenomRAT_SPDL_MTB{
	meta:
		description = "Trojan:BAT/VenomRAT.SPDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 08 11 05 08 5d 08 58 08 5d 13 09 07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 13 0a 02 11 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}