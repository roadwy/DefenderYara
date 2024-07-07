
rule VirTool_Win32_VBInject_OR_bit{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 0f 85 90 02 30 41 90 02 30 8b 53 2c 90 02 30 31 ca 90 02 30 83 fa 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_OR_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ad 83 f8 00 74 fa bb 57 8b ec 83 4b 4b 39 18 75 ef bb ee 0c 56 8d 4b 4b 39 58 04 75 e3 } //1
		$a_03_1 = {6a 00 6a 00 6a 01 81 04 24 90 01 02 00 00 ff d0 89 45 08 89 f9 eb 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_VBInject_OR_bit_3{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 30 00 00 00 90 02 20 64 ff 30 90 02 30 58 90 02 20 8b 40 0c 90 02 20 8b 40 14 90 00 } //1
		$a_03_1 = {c6 83 eb 04 90 02 20 8b 14 1f 90 02 20 31 f2 90 02 30 89 14 18 90 02 20 85 db 75 90 02 20 ff e0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_VBInject_OR_bit_4{
	meta:
		description = "VirTool:Win32/VBInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ad 83 f8 00 74 90 01 01 bb 57 8b ec 83 4b 4b 39 18 75 90 01 01 bb ee 0c 56 8d 4b 4b 39 58 04 90 00 } //1
		$a_03_1 = {c6 04 24 48 90 02 10 c6 44 24 01 65 90 02 10 c6 44 24 02 61 90 02 10 c6 44 24 03 70 90 02 10 c6 44 24 04 43 90 02 10 c6 44 24 05 72 90 02 10 c6 44 24 06 65 90 02 10 c6 44 24 07 61 90 02 10 c6 44 24 08 74 90 02 10 c6 44 24 09 65 90 00 } //1
		$a_03_2 = {ff 34 08 e9 90 01 04 8f 04 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}