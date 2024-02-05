
rule Trojan_BAT_Lokibot_ABXX_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ABXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0c 06 08 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 02 16 02 8e 69 6f 90 01 01 00 00 0a 0d 09 13 04 2b 00 11 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}