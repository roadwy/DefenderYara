
rule VirTool_BAT_Rummage{
	meta:
		description = "VirTool:BAT/Rummage,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_11_0 = {75 6d 6d 61 67 65 20 69 73 20 6c 69 63 65 6e 73 65 64 20 74 6f 20 20 28 69 73 73 75 65 20 30 29 20 66 6f 72 20 75 73 65 20 77 69 74 68 20 2e 00 } //1
	condition:
		((#a_11_0  & 1)*1) >=10
 
}