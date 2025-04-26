
rule Trojan_BAT_AgentTesla_GR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {42 61 73 65 43 68 61 6e 6e 65 6c 2e 4d 79 } //1 BaseChannel.My
		$a_81_1 = {42 61 73 65 43 68 61 6e 6e 65 6c 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 BaseChannel.Resources.resources
		$a_81_2 = {66 72 6f 6e 74 64 65 73 6b 5f 69 6e 76 65 6e 74 6f 72 79 43 6f 6e 6e 65 63 74 69 6f 6e 53 74 72 69 6e 67 } //1 frontdesk_inventoryConnectionString
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_4 = {61 70 70 6c 65 2e 63 6f 6d } //1 apple.com
		$a_81_5 = {50 6f 73 69 74 69 6f 6e } //1 Position
		$a_81_6 = {4c 65 6e 67 74 68 } //1 Length
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}