
rule Trojan_BAT_Marsilia_KAU_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 1f 28 62 09 1d 91 1f 21 61 6a 1f 20 62 09 18 91 20 ?? 00 00 00 61 6a 1f 38 62 09 16 91 1f 1f 61 6a 1e 62 09 1b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}