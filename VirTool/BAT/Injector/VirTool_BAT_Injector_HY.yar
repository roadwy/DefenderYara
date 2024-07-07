
rule VirTool_BAT_Injector_HY{
	meta:
		description = "VirTool:BAT/Injector.HY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 6e 64 6d 6b 65 79 } //1 rndmkey
		$a_01_1 = {53 63 72 69 62 65 } //1 Scribe
		$a_01_2 = {42 6f 74 6b 69 6c 6c } //1 Botkill
		$a_01_3 = {4b 69 6c 6c 41 6e 64 44 65 6c 65 74 65 } //1 KillAndDelete
		$a_01_4 = {45 72 61 73 65 53 } //1 EraseS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}