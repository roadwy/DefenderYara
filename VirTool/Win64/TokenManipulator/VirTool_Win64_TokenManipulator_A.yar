
rule VirTool_Win64_TokenManipulator_A{
	meta:
		description = "VirTool:Win64/TokenManipulator.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {6c 69 73 74 5f 74 6f 6b 65 6e 73 } //list_tokens  1
	condition:
		((#a_80_0  & 1)*1) >=1
 
}