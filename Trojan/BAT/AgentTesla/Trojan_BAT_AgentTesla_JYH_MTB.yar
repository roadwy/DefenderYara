
rule Trojan_BAT_AgentTesla_JYH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JYH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 08 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0d de 15 } //1
		$a_81_1 = {53 79 21 73 74 65 6d 2e 52 65 66 6c 21 65 63 74 69 6f 6e 2e 41 73 21 73 65 6d 62 6c 79 } //1 Sy!stem.Refl!ection.As!sembly
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}