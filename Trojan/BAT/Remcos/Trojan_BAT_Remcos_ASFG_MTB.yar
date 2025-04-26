
rule Trojan_BAT_Remcos_ASFG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ASFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 08 8e 69 5d 02 08 11 04 08 8e 69 5d 91 09 11 04 09 28 ?? 02 00 06 5d 28 ?? 02 00 06 61 28 ?? 02 00 06 08 11 04 17 58 08 8e 69 5d 91 28 ?? 02 00 06 59 20 00 01 00 00 58 28 ?? 02 00 06 28 ?? 02 00 06 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}