
rule VirTool_Win32_VBInject_OR_bit{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 0f 85 [0-30] 41 [0-30] 8b 53 2c [0-30] 31 ca [0-30] 83 fa 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_OR_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ad 83 f8 00 74 fa bb 57 8b ec 83 4b 4b 39 18 75 ef bb ee 0c 56 8d 4b 4b 39 58 04 75 e3 } //1
		$a_03_1 = {6a 00 6a 00 6a 01 81 04 24 ?? ?? 00 00 ff d0 89 45 08 89 f9 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_VBInject_OR_bit_3{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 30 00 00 00 [0-20] 64 ff 30 [0-30] 58 [0-20] 8b 40 0c [0-20] 8b 40 14 } //1
		$a_03_1 = {c6 83 eb 04 [0-20] 8b 14 1f [0-20] 31 f2 [0-30] 89 14 18 [0-20] 85 db 75 [0-20] ff e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_VBInject_OR_bit_4{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ad 83 f8 00 74 ?? bb 57 8b ec 83 4b 4b 39 18 75 ?? bb ee 0c 56 8d 4b 4b 39 58 04 } //1
		$a_03_1 = {c6 04 24 48 [0-10] c6 44 24 01 65 [0-10] c6 44 24 02 61 [0-10] c6 44 24 03 70 [0-10] c6 44 24 04 43 [0-10] c6 44 24 05 72 [0-10] c6 44 24 06 65 [0-10] c6 44 24 07 61 [0-10] c6 44 24 08 74 [0-10] c6 44 24 09 65 } //1
		$a_03_2 = {ff 34 08 e9 ?? ?? ?? ?? 8f 04 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}