
rule Trojan_BAT_AgentTesla_AKY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {47 61 6d 65 4d 61 6b 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 GameMaker.Resources.resources
		$a_81_1 = {47 61 6d 65 4d 61 6b 65 72 2e 66 72 6d 41 64 64 43 6f 6e 74 61 63 74 2e 72 65 73 6f 75 72 63 65 73 } //1 GameMaker.frmAddContact.resources
		$a_81_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_3 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_81_4 = {53 74 6f 70 47 72 65 79 } //1 StopGrey
		$a_81_5 = {52 65 61 64 4f 6e 6c 79 44 69 63 74 69 6f 6e 61 72 79 } //1 ReadOnlyDictionary
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //1 NewLateBinding
		$a_81_8 = {42 75 69 6c 64 65 72 49 6e 73 74 61 6e 74 69 61 74 69 6f 6e } //1 BuilderInstantiation
		$a_81_9 = {67 65 74 5f 53 74 6f 70 47 72 65 79 } //1 get_StopGrey
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}