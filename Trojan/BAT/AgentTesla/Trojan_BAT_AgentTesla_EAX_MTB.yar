
rule Trojan_BAT_AgentTesla_EAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 02 e7 02 eb 02 e7 02 e2 02 df 02 df 02 df 02 05 03 0b 03 df 02 eb 02 df 02 df 02 e1 02 05 03 e6 02 df 02 df 02 df 02 10 03 e5 02 f7 02 ce 02 e7 02 df 02 df 02 df 02 } //1
		$a_01_1 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //1 Bunifu_TextBox
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_EAX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 15 00 00 06 0a 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0b dd 03 00 00 00 26 de db 07 2a 90 00 } //2
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 38 00 37 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 WindowsFormsApp87.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}