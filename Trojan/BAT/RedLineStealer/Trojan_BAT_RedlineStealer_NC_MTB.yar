
rule Trojan_BAT_RedlineStealer_NC_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 15 00 00 00 00 02 06 8f 90 01 01 00 00 01 25 47 03 06 91 61 d2 52 00 06 17 59 0a 06 16 fe 04 16 fe 01 0b 07 3a dd ff ff ff 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}