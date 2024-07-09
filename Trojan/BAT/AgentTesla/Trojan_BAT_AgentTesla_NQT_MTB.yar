
rule Trojan_BAT_AgentTesla_NQT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 20 00 60 00 00 5d 06 08 20 00 60 00 00 5d 91 07 08 1f 16 5d 6f ?? ?? ?? 0a 61 06 08 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 08 15 58 0c 08 16 2f c2 } //1
		$a_81_1 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 } //1 System.Reflection.Assembly
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}