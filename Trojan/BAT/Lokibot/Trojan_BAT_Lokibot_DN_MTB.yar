
rule Trojan_BAT_Lokibot_DN_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 2b 32 7e 90 01 03 04 7e 90 01 03 04 06 7e 90 01 03 04 06 8e 69 5d 91 9e 7e 90 01 03 04 7e 90 01 03 04 7e 90 01 03 04 9e 7e 90 01 03 04 17 58 80 90 01 03 04 7e 90 01 03 04 20 00 01 00 00 32 c2 28 90 01 03 06 0f 00 28 90 01 03 06 7e 90 01 03 04 2a 90 00 } //01 00 
		$a_81_1 = {43 72 79 70 74 6f } //01 00 
		$a_81_2 = {63 69 70 68 65 72 } //01 00 
		$a_81_3 = {53 6c 65 65 70 } //00 00 
	condition:
		any of ($a_*)
 
}