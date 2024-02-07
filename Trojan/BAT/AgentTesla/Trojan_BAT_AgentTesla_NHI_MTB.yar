
rule Trojan_BAT_AgentTesla_NHI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 35 30 39 34 31 31 66 65 2d 62 64 37 66 2d 34 62 32 37 2d 62 32 34 32 2d 61 61 35 34 31 61 39 38 64 30 63 34 } //01 00  $509411fe-bd7f-4b27-b242-aa541a98d0c4
		$a_01_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_2 = {47 55 49 5f 43 6c 61 73 73 2e 51 51 51 51 51 2e 72 65 73 6f 75 72 63 65 } //01 00  GUI_Class.QQQQQ.resource
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}