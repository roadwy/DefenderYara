
rule VirTool_Win32_Obfuscator_AFT{
	meta:
		description = "VirTool:Win32/Obfuscator.AFT,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {60 e8 00 00 00 00 5d 83 ed 06 80 bd 3e 05 00 00 01 0f 84 48 02 00 00 c6 85 3e 05 00 00 01 8b c5 2b 85 4b 05 00 00 89 ad ce 05 00 00 89 85 8b 05 00 00 } //10
		$a_03_1 = {c7 45 cc 01 00 00 00 c7 45 c4 02 00 00 00 ff 75 dc 8d 45 c4 50 ff 75 e8 ff 75 e0 e8 ?? ?? ff ff 8b d0 8d 4d d4 e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 8b d0 8d 4d dc e8 ?? ?? ff ff 8d 4d d4 e8 ?? ?? ff ff 8d 4d c4 e8 ?? ?? ff ff } //10
		$a_03_2 = {8b 45 e8 3b 45 ac 0f 8f ?? 00 00 00 c7 45 cc 01 00 00 00 c7 45 c4 02 00 00 00 6a 01 } //10
		$a_01_3 = {50 45 2d 50 41 43 4b 3a 20 49 4d 50 4f 52 54 20 4c 44 52 20 45 52 52 4f 52 00 } //5 䕐倭䍁㩋䤠偍剏⁔䑌⁒剅佒R
		$a_01_4 = {41 44 3a 5c 50 72 6f 79 65 63 74 6f 31 2e 76 62 70 00 } //5 䑁尺牐祯捥潴⸱扶p
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=35
 
}