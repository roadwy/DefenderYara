
rule VirTool_BAT_Obfuscator_AT{
	meta:
		description = "VirTool:BAT/Obfuscator.AT,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {61 0c 06 16 07 6f 90 01 04 08 20 ff ff 00 00 5f d1 8c 90 01 04 06 07 17 58 6f 90 01 04 28 90 01 04 0a 07 17 58 90 00 } //1
		$a_01_1 = {20 b7 00 00 00 59 0c 08 1f 27 61 0c 08 20 d7 00 00 00 58 0c 08 07 59 0c 08 20 dd 00 00 00 59 0c 08 66 0c 08 20 a4 00 00 00 61 0c 08 07 61 } //1
		$a_03_2 = {0c 08 17 58 0c 08 07 58 0c 08 20 90 01 04 58 0c 08 07 61 0c 08 07 59 0c 08 17 59 0c 06 16 07 6f 90 01 04 08 20 ff ff 00 00 5f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}