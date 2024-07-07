
rule Trojan_BAT_LokiBot_DEN_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.DEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 43 6f 6e 74 72 6f 6c 44 61 72 6b 44 61 72 6b } //3 get_ControlDarkDark
		$a_81_1 = {48 72 6d 70 50 72 6f 67 72 61 6d } //3 HrmpProgram
		$a_81_2 = {48 72 6d 70 49 6e 74 65 72 70 72 65 74 65 72 2e 43 6f 6d 6d 61 6e 64 73 } //3 HrmpInterpreter.Commands
		$a_81_3 = {48 72 6d 70 49 6e 74 65 72 70 72 65 74 65 72 2e 4a 6f 75 72 6e 61 6c 73 } //3 HrmpInterpreter.Journals
		$a_81_4 = {52 61 7a 65 72 49 6e 73 74 61 6c 6c 65 72 } //3 RazerInstaller
		$a_81_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //3 DebuggingModes
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}