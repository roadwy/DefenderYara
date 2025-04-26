
rule Trojan_BAT_RedLine_KAU_MTB{
	meta:
		description = "Trojan:BAT/RedLine.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 04 08 1e 5d 9a 28 ?? 00 00 0a 03 08 91 28 ?? 01 00 06 28 ?? 00 00 0a 9c 08 17 d6 0c 08 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}