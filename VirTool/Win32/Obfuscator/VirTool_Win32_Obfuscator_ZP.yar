
rule VirTool_Win32_Obfuscator_ZP{
	meta:
		description = "VirTool:Win32/Obfuscator.ZP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_0b_0 = {89 44 24 1c 89 c7 50 68 22 07 e4 71 50 e8 ?? ?? ?? ?? 89 85 f4 fd ff ff 58 68 b6 74 75 5d 50 e8 ?? ?? ?? ?? 89 85 ec fd ff ff 68 50 46 b4 59 57 e8 } //1
		$a_03_1 = {81 c1 00 10 (00|01) 00 c7 01 90 90 90 90 90 90 90 90 c7 41 04 90 90 90 90 90 90 90 90 c7 41 08 90 90 90 90 90 90 90 90 81 c2 ?? ?? ?? ?? c6 02 e9 51 29 d1 89 4a 01 } //1
		$a_01_2 = {ff d2 01 f0 ff 70 fc ff 70 f8 5a 58 3d 2e 65 78 65 74 05 3d 2e 45 58 45 } //1
	condition:
		((#a_0b_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}