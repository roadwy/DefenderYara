
rule VirTool_BAT_QuasarRAT_ASC_bit{
	meta:
		description = "VirTool:BAT/QuasarRAT.ASC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {da 17 d6 8d 14 00 00 01 90 01 01 28 1d 00 00 0a 72 01 00 00 70 6f 1e 00 00 0a 90 01 03 2b 0a 90 00 } //1
		$a_03_1 = {8e b7 2f 26 90 01 01 16 30 00 90 01 02 8e b7 17 da 90 01 01 da 02 90 01 01 91 02 02 8e b7 17 da 91 61 90 01 03 8e b7 5d 91 61 9c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}