
rule VirTool_BAT_CryptInject_YY_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {0a 06 16 7e 90 01 03 04 a4 90 01 03 01 06 17 7e 90 01 03 04 a4 90 01 03 01 06 18 7e 90 01 03 04 a4 90 01 03 01 06 19 7e 90 01 03 04 a4 90 01 03 01 06 1a 7e 90 01 03 04 a4 90 01 03 01 06 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 07 28 90 01 03 06 dd 90 01 03 00 26 dd 90 01 03 00 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}