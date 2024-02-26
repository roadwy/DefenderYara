
rule Trojan_BAT_DeliveryCheck_B_dha{
	meta:
		description = "Trojan:BAT/DeliveryCheck.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_01_0 = {08 06 1a 58 4a 03 06 1a 58 4a 03 8e 69 5d 91 9e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_DeliveryCheck_B_dha_2{
	meta:
		description = "Trojan:BAT/DeliveryCheck.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2b 56 08 17 58 20 00 01 00 00 5d 0c 09 06 08 94 58 20 00 01 00 00 5d 0d 06 08 94 13 09 06 08 06 09 94 9e 06 09 11 09 9e 06 06 08 94 06 09 94 58 20 00 01 00 00 5d 94 1a 2c ac 13 0a 11 04 11 08 } //00 00 
	condition:
		any of ($a_*)
 
}