
rule VirTool_Win32_Obfuscator_PX{
	meta:
		description = "VirTool:Win32/Obfuscator.PX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 6b 59 6f 06 50 e8 } //2
		$a_03_1 = {8d 70 54 6a 04 50 8d 80 ?? ?? ?? ?? 51 91 90 09 07 00 59 8b 85 ?? f4 ff } //1
		$a_03_2 = {56 57 64 8b 35 18 00 00 00 8d 76 30 6a 04 50 8d 80 ?? ?? ?? ?? 51 91 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_PX_2{
	meta:
		description = "VirTool:Win32/Obfuscator.PX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {51 8d 52 7b 59 8d 40 7b 53 8d 40 85 5b 8d 52 85 51 8d 52 7b 59 8d 40 7b } //1
		$a_03_1 = {e8 f3 10 00 00 c6 85 90 90 fd ff ff 57 8d ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? c6 85 91 fd ff ff 49 } //1
		$a_03_2 = {68 00 3e 96 bc ff b5 28 f4 ff ff e8 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}
rule VirTool_Win32_Obfuscator_PX_3{
	meta:
		description = "VirTool:Win32/Obfuscator.PX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 03 00 00 "
		
	strings :
		$a_13_0 = {85 91 fd ff ff 44 90 02 20 c6 85 92 fd ff ff 56 90 02 20 c6 85 93 fd ff ff 41 90 02 20 c6 85 94 fd ff ff 50 90 00 01 } //1
		$a_c6_1 = {91 fd ff ff 49 90 01 0c c6 85 92 fd ff ff 4e 90 01 0c c6 } //9984
		$a_ff_2 = {53 90 01 0c c6 85 94 fd ff ff 50 90 00 01 00 27 13 c6 85 50 fd ff ff 61 90 01 0c c6 85 51 fd ff ff 64 90 01 0c c6 85 52 fd ff ff 76 90 01 0c c6 85 53 fd ff ff 61 90 00 00 00 5d 04 00 00 3e 7c 02 80 5c 1e 00 00 3f 7c 02 80 00 00 01 00 08 00 08 00 ac 21 56 42 2e 59 41 59 00 00 01 40 05 82 70 00 04 00 80 10 00 00 9d fc 05 7f d4 0b cb 3a d8 64 2e 80 c0 ff 00 80 5d 04 00 00 3f 7c 02 80 5c 1e 00 00 41 7c 02 80 00 00 01 00 08 00 08 00 ac 21 47 79 70 6c 69 74 00 00 01 40 05 82 70 00 04 00 50 14 00 00 47 47 1c 15 2c c5 92 74 00 00 22 00 dd c1 1b fe 02 00 00 00 5d 04 00 00 41 7c 02 80 5c 20 00 00 42 7c 02 80 00 00 01 00 08 00 0a 00 ac 21 47 79 70 6c 69 74 2e 41 00 00 03 40 05 82 70 00 04 00 67 16 00 00 ef 81 46 06 96 dc 6f 1d e3 cd f5 a6 00 9c 00 00 01 20 e3 } //-27771
	condition:
		((#a_13_0  & 1)*1+(#a_c6_1  & 1)*9984+(#a_ff_2  & 1)*-27771) >=1
 
}