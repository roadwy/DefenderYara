
rule VirTool_BAT_AsmInject_C{
	meta:
		description = "VirTool:BAT/AsmInject.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1f 02 06 8f 90 01 01 00 00 01 25 71 90 1b 00 00 00 01 03 06 03 8e 69 5d 91 61 d2 81 90 1b 00 00 00 01 06 17 58 0a 06 02 8e 69 32 db 02 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 14 7e 90 01 01 00 00 04 6f 90 01 01 00 00 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}