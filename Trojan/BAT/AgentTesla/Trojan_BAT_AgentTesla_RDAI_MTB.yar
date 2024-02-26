
rule Trojan_BAT_AgentTesla_RDAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 08 91 66 03 5f 60 d2 9c 00 08 17 58 0c } //00 00 
	condition:
		any of ($a_*)
 
}