
rule Trojan_BAT_AgentTesla_SPEQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 01 72 01 00 00 70 20 00 01 00 00 14 14 14 6f 90 01 03 0a 13 02 38 0f 00 00 00 7e 03 00 00 04 6f 90 01 03 0a 38 0c 00 00 00 11 02 39 05 00 00 00 38 e5 ff ff ff 90 00 } //01 00 
		$a_01_1 = {6b 00 65 00 64 00 61 00 69 00 6f 00 72 00 61 00 6e 00 67 00 6d 00 65 00 6c 00 61 00 79 00 75 00 2e 00 78 00 79 00 7a 00 } //00 00  kedaiorangmelayu.xyz
	condition:
		any of ($a_*)
 
}