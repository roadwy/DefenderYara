
rule Trojan_BAT_Zbot_KAA_MTB{
	meta:
		description = "Trojan:BAT/Zbot.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {58 0a 06 20 90 01 02 00 00 58 0a 04 1f 19 64 04 1d 62 60 10 02 06 20 90 01 02 00 00 58 0a 06 20 90 01 02 00 00 58 0a 04 03 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}