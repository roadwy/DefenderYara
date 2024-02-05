
rule VirTool_BAT_CryptInject_MTB{
	meta:
		description = "VirTool:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {d0 0e 00 00 01 28 90 01 01 00 00 0a 72 90 01 03 70 17 fe 0e 03 00 20 90 01 04 20 90 01 04 20 90 01 04 61 20 90 01 04 40 10 00 00 00 20 02 00 00 00 fe 0e 03 00 fe 90 01 02 00 00 01 58 00 8d 01 00 00 01 0b 07 16 fe 0e 04 00 20 90 01 04 20 90 01 04 20 90 01 04 61 20 90 01 04 40 90 01 01 00 00 00 20 90 01 01 00 00 00 fe 0e 04 00 fe 90 01 02 00 00 01 58 90 00 } //01 00 
		$a_02_1 = {d0 0e 00 00 01 28 90 01 03 0a 72 90 01 03 70 17 8d 01 00 00 01 0b 07 16 28 90 01 01 00 00 06 28 90 01 01 00 00 0a a2 07 28 90 01 01 00 00 06 75 90 01 01 00 00 01 0a d0 90 01 01 00 00 02 28 90 01 01 00 00 0a 72 90 01 03 70 17 8d 01 00 00 01 0c 08 16 06 a2 08 28 0e 00 00 06 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_CryptInject_MTB_2{
	meta:
		description = "VirTool:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 66 75 63 6b 2e 65 78 65 } //01 00 
		$a_01_1 = {49 00 6e 00 6a 00 65 00 63 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}