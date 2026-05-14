
rule Trojan_BAT_DarkTortilla_AXP_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 08 38 57 ff ff ff 16 2b f6 07 11 04 02 11 04 91 20 94 00 00 00 61 9c 00 18 13 08 38 3d ff ff ff 00 07 11 04 02 11 04 91 9c 00 18 13 08 38 2b ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}