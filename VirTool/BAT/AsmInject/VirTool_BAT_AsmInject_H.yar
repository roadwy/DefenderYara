
rule VirTool_BAT_AsmInject_H{
	meta:
		description = "VirTool:BAT/AsmInject.H,SIGNATURE_TYPE_PEHSTR,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 4c 00 6f 00 61 00 64 00 00 15 45 00 6e 00 74 00 72 00 79 00 70 00 6f 00 69 00 6e 00 74 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=100
 
}