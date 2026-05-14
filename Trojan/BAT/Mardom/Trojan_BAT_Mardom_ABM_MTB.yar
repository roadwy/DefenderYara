
rule Trojan_BAT_Mardom_ABM_MTB{
	meta:
		description = "Trojan:BAT/Mardom.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 00 00 fe 0c 01 00 fe 09 00 00 fe 0c 01 00 91 fe 09 01 00 fe 0c 01 00 fe 09 01 00 8e 69 5d 91 61 d2 9c fe 0c 01 00 20 01 00 00 00 58 fe 0e 01 00 fe 0c 01 00 fe 09 00 00 8e 69 3f bf ff ff ff fe 0c 00 00 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}