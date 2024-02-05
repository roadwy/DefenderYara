
rule VirTool_BAT_Obfuscator_CB_bit{
	meta:
		description = "VirTool:BAT/Obfuscator.CB!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 07 02 07 91 1f 0f 61 d2 9c 07 1f 0f 58 0b } //00 00 
	condition:
		any of ($a_*)
 
}