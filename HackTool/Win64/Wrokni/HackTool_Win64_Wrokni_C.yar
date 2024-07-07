
rule HackTool_Win64_Wrokni_C{
	meta:
		description = "HackTool:Win64/Wrokni.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ba 5f 4c 45 5f } //1
		$a_01_1 = {56 00 69 00 64 00 65 00 6f 00 44 00 72 00 69 00 76 00 65 00 72 00 } //1 VideoDriver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}