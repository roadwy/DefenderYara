
rule VirTool_Win32_Obfuscator_BZF{
	meta:
		description = "VirTool:Win32/Obfuscator.BZF,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 46 d9 05 90 01 03 10 33 c9 dc 0d 90 01 03 10 dc 05 90 01 03 10 dc 25 90 01 03 10 dc 25 90 01 03 10 d9 1d 90 01 03 10 8d 81 90 01 03 10 8a 10 80 f2 90 01 01 80 ea 90 01 01 41 88 10 81 f9 00 2c 00 00 72 e7 90 09 07 00 80 3d 90 01 03 10 4d 90 00 } //1
		$a_03_1 = {b9 4d 5a 00 00 d9 1d 90 01 03 10 d9 05 90 01 03 10 d9 1d 90 01 03 10 66 39 08 75 da 53 8b 58 3c 03 d8 81 3b 50 45 00 00 74 07 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}