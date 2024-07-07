
rule VirTool_BAT_Injector_VD_bit{
	meta:
		description = "VirTool:BAT/Injector.VD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 25 4b 04 06 1f 0f 5f 95 61 54 04 06 1f 0f 5f 04 06 1f 0f 5f 95 03 25 1a 58 10 01 4b 61 20 84 e2 03 78 58 9e 06 17 58 0a 07 17 58 0b 07 02 37 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}