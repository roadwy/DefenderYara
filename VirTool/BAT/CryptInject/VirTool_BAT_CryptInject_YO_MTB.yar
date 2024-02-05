
rule VirTool_BAT_CryptInject_YO_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {17 da 91 1f 90 01 01 61 90 02 02 02 8e 90 01 01 17 d6 90 02 07 02 8e 90 01 01 17 da 90 02 0a 11 90 01 01 02 11 90 01 01 91 90 02 02 61 07 90 02 02 91 61 b4 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}