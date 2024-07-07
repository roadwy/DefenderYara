
rule Trojan_BAT_AgentTesla_PE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 52 00 65 00 63 00 75 00 72 00 73 00 69 00 76 00 65 00 46 00 6f 00 72 00 6d 00 43 00 72 00 65 00 61 00 74 00 65 00 } //1 WinForms_RecursiveFormCreate
		$a_01_1 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 53 00 65 00 65 00 49 00 6e 00 6e 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 } //1 WinForms_SeeInnerException
		$a_01_2 = {24 65 65 31 33 38 61 37 33 2d 63 36 30 34 2d 34 31 65 34 2d 39 64 66 66 2d 62 37 61 30 31 34 32 66 36 34 65 66 } //1 $ee138a73-c604-41e4-9dff-b7a0142f64ef
		$a_01_3 = {46 69 6f 6e 6e 43 68 61 72 61 63 74 65 72 53 68 65 65 74 2e 57 65 6c 63 6f 6d 65 2e 72 65 73 6f 75 72 63 65 73 } //1 FionnCharacterSheet.Welcome.resources
		$a_01_4 = {46 69 6f 6e 6e 43 68 61 72 61 63 74 65 72 53 68 65 65 74 2e 4c 43 44 45 6d 75 6c 61 74 6f 72 46 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 FionnCharacterSheet.LCDEmulatorFrm.resources
		$a_01_5 = {46 69 6f 6e 6e 43 68 61 72 61 63 74 65 72 53 68 65 65 74 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 FionnCharacterSheet.Resources.resources
		$a_01_6 = {46 69 6f 6e 6e 43 68 61 72 61 63 74 65 72 53 68 65 65 74 2e 53 6b 69 6c 6c 73 46 6f 63 75 73 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 FionnCharacterSheet.SkillsFocuses.resources
		$a_01_7 = {46 69 6f 6e 6e 43 68 61 72 61 63 74 65 72 53 68 65 65 74 2e 4d 75 6c 74 69 70 6c 65 42 6c 6f 63 6b 73 2e 72 65 73 6f 75 72 63 65 73 } //1 FionnCharacterSheet.MultipleBlocks.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}