
rule Trojan_BAT_AgentTesla_MBY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 72 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 crm.Properties.Resources.resources
		$a_01_1 = {32 33 66 34 32 66 36 63 31 37 35 63 } //2 23f42f6c175c
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}