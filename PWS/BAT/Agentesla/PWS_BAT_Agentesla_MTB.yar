
rule PWS_BAT_Agentesla_MTB{
	meta:
		description = "PWS:BAT/Agentesla!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 64 00 65 00 6c 00 73 00 43 00 6f 00 72 00 65 00 } //01 00  ModelsCore
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  CheckRemoteDebuggerPresent
		$a_01_3 = {53 6e 61 6b 65 42 4f 54 } //01 00  SnakeBOT
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_5 = {4d 6f 64 65 6c 73 43 6f 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  ModelsCore.Properties.Resources
		$a_01_6 = {46 46 36 34 35 45 30 45 43 34 39 33 43 42 36 43 46 46 41 35 42 32 46 46 41 31 35 34 38 36 37 30 35 35 38 39 41 42 46 45 42 44 38 34 35 46 37 35 33 41 41 39 41 34 37 42 32 42 31 34 39 31 45 37 } //00 00  FF645E0EC493CB6CFFA5B2FFA15486705589ABFEBD845F753AA9A47B2B1491E7
	condition:
		any of ($a_*)
 
}