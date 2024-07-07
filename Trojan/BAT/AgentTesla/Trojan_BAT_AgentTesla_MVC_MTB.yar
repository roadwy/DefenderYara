
rule Trojan_BAT_AgentTesla_MVC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8f 36 00 00 01 25 47 09 11 10 09 8e 69 5d 91 61 d2 52 } //1
		$a_00_1 = {57 65 41 72 65 43 68 6d 6e 65 74 2e 70 64 62 } //1 WeAreChmnet.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}