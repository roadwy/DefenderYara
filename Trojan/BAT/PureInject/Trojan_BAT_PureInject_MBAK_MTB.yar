
rule Trojan_BAT_PureInject_MBAK_MTB{
	meta:
		description = "Trojan:BAT/PureInject.MBAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 00 70 00 62 00 6a 00 79 00 72 00 72 00 70 00 73 00 78 00 7a 00 6e 00 73 00 66 00 69 00 76 00 } //00 00 
	condition:
		any of ($a_*)
 
}