
rule Trojan_BAT_Zusy_AZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 11 05 11 07 11 08 11 08 8e 69 16 28 ?? 01 00 06 2d 02 1c 2a 11 05 16 e0 28 ?? 01 00 0a 7e ?? 01 00 04 11 06 11 07 16 16 e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}