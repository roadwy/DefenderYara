
rule Trojan_BAT_StormKitty_KAA_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 5d 91 61 20 00 01 00 00 58 06 08 06 8e 69 5d 91 59 20 00 01 00 00 5d d2 9c 00 08 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}