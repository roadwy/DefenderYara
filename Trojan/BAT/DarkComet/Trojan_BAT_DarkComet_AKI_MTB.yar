
rule Trojan_BAT_DarkComet_AKI_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1b 03 06 7e 03 00 00 04 5d 91 0b 02 06 02 06 91 07 61 28 ?? 00 00 0a 9c 06 17 58 0a 06 02 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}