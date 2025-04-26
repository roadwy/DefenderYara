
rule HackTool_Win64_ShellCodeMarte_ZM_MTB{
	meta:
		description = "HackTool:Win64/ShellCodeMarte.ZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 ca 8a 04 19 41 88 04 1b 40 88 34 19 41 0f b6 04 1b 48 03 c6 0f b6 c0 8a 0c 18 42 32 0c 02 41 88 08 49 ff c0 49 83 e9 01 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}