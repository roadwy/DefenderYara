
rule Trojan_BAT_AgentTesla_SOG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {45 6d 70 6c 6f 79 65 65 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 } //1 EmployeeManagementSystem.Properties
		$a_81_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_2 = {37 4b 41 59 51 37 38 35 34 37 37 34 37 32 54 39 34 34 35 45 37 34 } //1 7KAYQ785477472T9445E74
		$a_81_3 = {24 33 33 61 37 31 64 34 62 2d 34 63 64 34 2d 34 30 65 34 2d 39 62 38 35 2d 38 37 38 61 66 62 38 34 61 61 31 65 } //1 $33a71d4b-4cd4-40e4-9b85-878afb84aa1e
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}