
rule VirTool_BAT_CryptInject_YL_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 17 00 00 0a 9c 06 07 17 58 11 04 11 05 28 17 00 00 0a 68 1e 63 9c 06 07 06 07 91 1f 32 61 9c 06 07 06 07 91 07 59 1f 1e 59 9c 06 07 06 07 91 1f 0a 61 9c 06 07 17 58 06 07 17 58 91 1f 32 61 9c 06 07 17 58 06 07 17 58 91 07 59 1f 1f 59 9c 06 07 17 58 06 07 17 58 91 1f 0a 61 9c 11 05 17 58 13 05 07 18 58 0b 11 05 11 04 28 32 00 00 06 } //00 00 
	condition:
		any of ($a_*)
 
}