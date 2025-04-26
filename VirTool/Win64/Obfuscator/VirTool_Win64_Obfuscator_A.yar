
rule VirTool_Win64_Obfuscator_A{
	meta:
		description = "VirTool:Win64/Obfuscator.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_13_0 = {45 d1 8b 46 24 8b 4e 0c 25 00 00 00 08 eb 90 14 0b d0 8b 46 08 48 03 0b 90 00 01 } //1
		$a_48_1 = {7b 18 8b 41 3c 48 03 c1 0f b7 50 14 48 8d 74 02 18 } //6912
	condition:
		((#a_13_0  & 1)*1+(#a_48_1  & 1)*6912) >=2
 
}