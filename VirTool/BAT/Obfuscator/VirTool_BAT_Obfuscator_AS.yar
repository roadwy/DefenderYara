
rule VirTool_BAT_Obfuscator_AS{
	meta:
		description = "VirTool:BAT/Obfuscator.AS,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 71 70 4b 51 51 62 53 47 46 61 6c 73 65 50 71 70 4b 51 51 62 53 47 50 71 70 4b 51 51 62 53 47 46 61 6c 73 65 50 71 70 4b 51 51 62 53 47 } //1 PqpKQQbSGFalsePqpKQQbSGPqpKQQbSGFalsePqpKQQbSG
	condition:
		((#a_01_0  & 1)*1) >=1
 
}