
rule Trojan_BAT_AgentTesla_NVD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 0b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 b6 00 00 00 18 00 00 00 31 01 00 00 fc 02 00 00 18 02 00 00 75 01 00 00 ca 05 00 00 49 00 00 00 10 } //1
		$a_01_1 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //1 Bunifu_TextBox
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}