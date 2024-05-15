
rule Trojan_BAT_PureLogsStealer_B_MTB{
	meta:
		description = "Trojan:BAT/PureLogsStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 00 11 06 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 16 11 06 8e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}