
rule VirTool_BAT_Obfuscator_AJ{
	meta:
		description = "VirTool:BAT/Obfuscator.AJ,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 76 74 6f 5f 42 6f 74 2e 65 78 65 } //10 Avto_Bot.exe
		$a_00_1 = {5c 00 4d 00 73 00 4d 00 70 00 45 00 6e 00 67 00 2e 00 65 00 78 00 65 00 } //1 \MsMpEng.exe
		$a_00_2 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 } //1 svchost
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=12
 
}