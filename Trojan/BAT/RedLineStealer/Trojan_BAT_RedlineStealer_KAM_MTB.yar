
rule Trojan_BAT_RedlineStealer_KAM_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 02 04 08 1e 5d 9a 28 ?? 00 00 0a 03 08 91 28 ?? 00 00 06 28 ?? 00 00 0a 9c 08 17 d6 0c 08 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}