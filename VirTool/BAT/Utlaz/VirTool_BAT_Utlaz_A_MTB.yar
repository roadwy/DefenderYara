
rule VirTool_BAT_Utlaz_A_MTB{
	meta:
		description = "VirTool:BAT/Utlaz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 6d 70 6c 61 6e 74 43 6f 6d 6d 61 6e 64 73 49 6e 69 74 } //01 00  ImplantCommandsInit
		$a_81_1 = {50 6f 6c 6c 49 6d 70 6c 61 6e 74 } //01 00  PollImplant
		$a_81_2 = {49 6d 70 6c 61 6e 74 54 61 73 6b } //01 00  ImplantTask
		$a_81_3 = {45 78 65 63 75 74 65 41 73 73 65 6d 4d 65 74 68 6f 64 } //01 00  ExecuteAssemMethod
		$a_81_4 = {48 54 54 50 43 6f 6d 6d 73 } //01 00  HTTPComms
		$a_81_5 = {49 6d 70 6c 61 6e 74 44 61 74 61 55 74 69 6c 73 } //01 00  ImplantDataUtils
		$a_81_6 = {43 4d 44 53 68 65 6c 6c } //01 00  CMDShell
		$a_81_7 = {50 53 53 68 65 6c 6c } //00 00  PSShell
	condition:
		any of ($a_*)
 
}