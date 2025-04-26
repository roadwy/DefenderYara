
rule Trojan_BAT_Nanobot_SPDO_MTB{
	meta:
		description = "Trojan:BAT/Nanobot.SPDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 07 08 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}