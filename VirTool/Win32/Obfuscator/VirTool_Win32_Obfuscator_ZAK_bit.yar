
rule VirTool_Win32_Obfuscator_ZAK_bit{
	meta:
		description = "VirTool:Win32/Obfuscator.ZAK!bit,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 c8 03 c3 68 90 01 03 00 8a 14 19 88 14 30 ff 15 90 01 03 00 60 8b 4d 08 8a 45 ff d3 e3 33 db 0b 1d 90 01 03 00 03 d9 8a 33 90 90 c1 ea 08 90 90 33 c2 88 03 90 00 } //2
		$a_03_1 = {b1 64 b0 6c 68 90 01 04 88 4c 90 01 02 88 44 90 01 02 88 44 90 01 02 c6 44 90 01 02 2e 88 4c 90 01 02 88 44 90 01 02 88 44 90 01 02 c6 44 90 01 02 00 90 00 } //1
		$a_01_2 = {33 c9 8a 0c 10 81 e9 8b 00 00 00 75 65 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}