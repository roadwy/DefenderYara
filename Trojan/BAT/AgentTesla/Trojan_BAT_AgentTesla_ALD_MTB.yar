
rule Trojan_BAT_AgentTesla_ALD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ALD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0c 00 00 0a 00 "
		
	strings :
		$a_81_0 = {47 61 6d 65 72 5f 43 6c 6f 63 6b 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //0a 00  Gamer_Clock.Resources.resources
		$a_81_1 = {47 61 6d 65 72 5f 43 6c 6f 63 6b 2e 69 42 61 73 65 54 6f 6f 6c 73 2e 72 65 73 6f 75 72 63 65 73 } //0a 00  Gamer_Clock.iBaseTools.resources
		$a_81_2 = {4d 6f 75 73 65 4d 61 6e 61 67 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //0a 00  MouseManager.Resources.resources
		$a_81_3 = {4d 6f 75 73 65 4d 61 6e 61 67 65 72 2e 66 72 6d 4f 70 74 69 6f 6e 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  MouseManager.frmOptions.resources
		$a_81_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_5 = {42 69 74 6d 61 70 } //01 00  Bitmap
		$a_81_6 = {53 74 6f 70 47 72 65 79 } //01 00  StopGrey
		$a_81_7 = {52 65 61 64 4f 6e 6c 79 44 69 63 74 69 6f 6e 61 72 79 } //01 00  ReadOnlyDictionary
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_9 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //01 00  NewLateBinding
		$a_81_10 = {42 75 69 6c 64 65 72 49 6e 73 74 61 6e 74 69 61 74 69 6f 6e } //01 00  BuilderInstantiation
		$a_81_11 = {67 65 74 5f 53 74 6f 70 47 72 65 79 } //00 00  get_StopGrey
	condition:
		any of ($a_*)
 
}