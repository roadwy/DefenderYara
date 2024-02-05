
rule VirTool_BAT_CryptInject_CG_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7c 00 7c 00 49 00 7c 00 45 00 7c 00 7c 00 } //01 00 
		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}