
rule Trojan_BAT_AgentTesla_EP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {07 11 05 02 11 05 91 06 61 09 08 91 61 b4 9c 08 03 6f 90 01 03 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 11 05 17 d6 13 05 90 00 } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_EP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {50 4f 53 5f 53 61 6c 65 73 5f 61 6e 64 5f 49 6e 76 65 6e 74 6f 72 79 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 POS_Sales_and_Inventory.My.Resources
		$a_81_1 = {50 4f 53 5f 53 61 6c 65 73 5f 61 6e 64 5f 49 6e 76 65 6e 74 6f 72 79 2e 49 53 4f 2e 72 65 73 6f 75 72 63 65 73 } //1 POS_Sales_and_Inventory.ISO.resources
		$a_81_2 = {53 61 6d 70 6c 65 20 50 4f 53 20 40 64 65 61 73 70 6f 5f 73 74 75 64 69 6f 73 } //1 Sample POS @deaspo_studios
		$a_81_3 = {43 75 72 72 65 6e 74 43 6c 6f 63 6b 53 70 65 65 64 } //1 CurrentClockSpeed
		$a_81_4 = {4d 6f 74 68 65 72 62 6f 61 72 64 20 4e 61 6d 65 } //1 Motherboard Name
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_7 = {74 65 6d 70 2e 74 78 74 } //1 temp.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}