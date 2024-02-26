
rule Trojan_BAT_Tedy_NC_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 0f 2c 16 11 04 17 6a da b7 17 d6 17 da 17 d6 17 da 17 d6 } //00 00 
	condition:
		any of ($a_*)
 
}