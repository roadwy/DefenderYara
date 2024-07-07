
rule VirTool_BAT_AsmInject_G{
	meta:
		description = "VirTool:BAT/AsmInject.G,SIGNATURE_TYPE_PEHSTR,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 65 78 74 65 72 5f 63 72 79 70 74 32 2e 65 78 65 } //1 Dexter_crypt2.exe
	condition:
		((#a_01_0  & 1)*1) >=100
 
}