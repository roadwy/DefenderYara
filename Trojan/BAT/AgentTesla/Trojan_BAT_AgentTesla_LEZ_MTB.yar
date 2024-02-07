
rule Trojan_BAT_AgentTesla_LEZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 28 90 01 03 0a 6f 90 01 03 0a 26 07 17 58 0b 07 02 6f 90 01 03 0a 32 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 } //00 00  FromBase64
	condition:
		any of ($a_*)
 
}