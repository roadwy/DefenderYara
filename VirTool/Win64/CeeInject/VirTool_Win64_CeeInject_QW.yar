
rule VirTool_Win64_CeeInject_QW{
	meta:
		description = "VirTool:Win64/CeeInject.QW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 0f 41 83 e1 03 47 8a 0c 08 44 30 0c 01 48 ff c0 39 d0 41 89 c1 7c ea } //1
		$a_01_1 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } //1 %c%c%c%c%c%c%c%c%cMSSE-%d-server
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}