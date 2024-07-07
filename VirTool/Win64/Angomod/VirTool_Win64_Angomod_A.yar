
rule VirTool_Win64_Angomod_A{
	meta:
		description = "VirTool:Win64/Angomod.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 ea 00 20 22 00 74 1a 83 fa 04 74 07 48 83 67 38 00 } //1
		$a_01_1 = {b9 80 25 00 00 66 39 08 73 09 48 8b bf 90 03 00 00 eb 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}