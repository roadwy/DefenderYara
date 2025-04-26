
rule Trojan_BAT_AgentTesla_JL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 95 a2 29 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 68 00 00 00 1c 00 00 00 8c 05 00 00 15 0c } //2
		$a_01_1 = {53 68 72 6d 6f 74 61 5f 48 79 67 61 2e 4d 79 } //2 Shrmota_Hyga.My
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}