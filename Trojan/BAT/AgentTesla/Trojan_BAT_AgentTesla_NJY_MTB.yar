
rule Trojan_BAT_AgentTesla_NJY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 06 00 00 1e 00 "
		
	strings :
		$a_01_0 = {24 32 63 37 37 62 36 66 37 2d 32 38 32 61 2d 34 62 63 39 2d 61 35 31 30 2d 61 37 66 65 61 65 32 37 36 64 34 64 } //1e 00  $2c77b6f7-282a-4bc9-a510-a7feae276d4d
		$a_01_1 = {24 61 32 30 36 39 36 39 65 2d 31 64 63 62 2d 34 37 39 39 2d 39 39 32 66 2d 64 66 65 34 32 39 62 38 66 39 65 38 } //0a 00  $a206969e-1dcb-4799-992f-dfe429b8f9e8
		$a_01_2 = {54 68 75 6d 62 6e 61 69 6c 5f 48 61 6e 64 6c 65 72 2e 52 65 73 6f 75 72 63 65 } //0a 00  Thumbnail_Handler.Resource
		$a_01_3 = {52 61 69 6e 62 6f 77 55 49 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 } //01 00  RainbowUI.Properties.Resource
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}