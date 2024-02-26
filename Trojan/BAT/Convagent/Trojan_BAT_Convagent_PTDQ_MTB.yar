
rule Trojan_BAT_Convagent_PTDQ_MTB{
	meta:
		description = "Trojan:BAT/Convagent.PTDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 7b 03 00 00 04 6f 17 00 00 0a 06 6f 18 00 00 0a 6f 19 00 00 0a 17 } //00 00 
	condition:
		any of ($a_*)
 
}