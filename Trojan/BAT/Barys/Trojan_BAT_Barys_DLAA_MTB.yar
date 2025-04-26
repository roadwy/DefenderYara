
rule Trojan_BAT_Barys_DLAA_MTB{
	meta:
		description = "Trojan:BAT/Barys.DLAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 06 11 04 28 ?? 00 00 06 0d 06 11 04 28 ?? 00 00 06 13 05 11 05 17 da 17 d6 8d ?? 00 00 01 0c 09 08 16 11 05 28 ?? 00 00 0a 08 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}