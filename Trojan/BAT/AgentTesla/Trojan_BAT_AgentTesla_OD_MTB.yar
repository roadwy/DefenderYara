
rule Trojan_BAT_AgentTesla_OD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {67 65 69 72 2e 4d 79 } //1 geir.My
		$a_81_1 = {53 74 61 6e 6b 6f 76 69 } //1 Stankovi
		$a_81_2 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 Create__Instance__
		$a_81_3 = {67 65 74 5f 53 65 74 74 69 6e 67 73 } //1 get_Settings
		$a_81_4 = {73 65 74 5f 44 6f 75 62 6c 65 42 75 66 66 65 72 65 64 } //1 set_DoubleBuffered
		$a_81_5 = {67 65 74 5f 54 72 61 6e 73 70 61 72 65 6e 74 } //1 get_Transparent
		$a_81_6 = {73 65 74 5f 42 61 63 6b 43 6f 6c 6f 72 } //1 set_BackColor
		$a_81_7 = {5f 70 61 73 73 6d 61 73 6b } //1 _passmask
		$a_81_8 = {4d 61 72 6c 65 74 74 } //1 Marlett
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}