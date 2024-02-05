
rule Trojan_BAT_Lokibot_WJYF_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.WJYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 24 00 06 07 72 90 01 03 70 07 72 90 01 03 70 28 90 01 03 0a 5d 28 90 01 03 0a 06 07 91 61 d2 9c 00 07 17 58 0b 07 06 8e 69 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_2 = {54 6f 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}