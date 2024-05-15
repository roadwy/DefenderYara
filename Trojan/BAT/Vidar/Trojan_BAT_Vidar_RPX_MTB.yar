
rule Trojan_BAT_Vidar_RPX_MTB{
	meta:
		description = "Trojan:BAT/Vidar.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 11 11 13 11 13 07 58 9e 11 13 17 58 13 13 11 13 11 11 8e 69 32 e9 11 0f 17 58 13 0f 11 0f 03 8e 69 3f 5a ff ff ff 11 0e 17 58 13 0e 11 0e 17 3f 44 ff ff ff 2a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Vidar_RPX_MTB_2{
	meta:
		description = "Trojan:BAT/Vidar.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 11 11 13 11 13 07 58 9e 11 13 17 58 13 13 11 13 11 11 8e 69 3f e6 ff ff ff 11 0f 17 58 13 0f 11 0f 03 8e 69 3f 48 ff ff ff 11 0e 17 58 13 0e 11 0e 17 3f 32 ff ff ff 2a } //00 00 
	condition:
		any of ($a_*)
 
}