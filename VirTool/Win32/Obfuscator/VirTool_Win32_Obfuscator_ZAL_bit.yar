
rule VirTool_Win32_Obfuscator_ZAL_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.ZAL!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 54 24 14 8b 0d 90 01 03 00 02 c3 5b 32 c2 88 04 31 8b 44 24 0c 83 f8 10 75 02 90 00 } //2
		$a_03_1 = {64 8b 1d 18 00 00 00 90 02 20 8b 51 30 90 02 20 8b 48 0c 90 02 20 8b 42 1c 90 02 20 8b 51 08 90 00 } //1
		$a_03_2 = {33 d2 8a 51 01 83 ea 4c 85 d2 74 04 ff e3 eb 90 01 01 b8 90 00 } //1
		$a_03_3 = {8a 10 88 11 a0 90 01 03 00 50 8b 4d 90 01 01 51 8b 55 90 01 01 52 e8 90 01 03 00 83 c4 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}