
rule VirTool_BAT_CryptInject_CF_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 0f 00 00 0a 26 16 0a 2b 0c 28 03 00 00 06 2c 01 2a 06 17 58 0a 06 1b 32 f0 2a } //01 00 
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}