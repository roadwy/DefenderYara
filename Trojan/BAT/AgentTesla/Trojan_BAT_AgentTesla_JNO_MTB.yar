
rule Trojan_BAT_AgentTesla_JNO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 07 93 03 07 03 8e 69 5d 93 61 d1 6f 90 01 03 0a 26 07 17 58 0b 07 02 8e 69 32 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}