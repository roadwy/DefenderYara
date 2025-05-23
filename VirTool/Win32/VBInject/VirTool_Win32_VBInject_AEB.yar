
rule VirTool_Win32_VBInject_AEB{
	meta:
		description = "VirTool:Win32/VBInject.AEB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 74 ff 6c 74 ff 1b 06 00 2a 31 74 ff 6c 74 ff 1b 07 00 2a 31 74 ff 6c 74 ff 1b 08 00 2a 31 74 ff 6c 74 ff 1b 09 00 2a 31 74 ff 6c 74 ff 1b 0a 00 2a 31 74 ff 6c 74 ff 1b 0b 00 2a 31 74 ff 6c 74 ff 1b 0c 00 2a 31 74 ff 6c 74 ff 1b 0d 00 2a 31 74 ff } //1
		$a_01_1 = {38 00 31 00 37 00 43 00 31 00 44 00 46 00 43 00 34 00 33 00 34 00 33 00 } //1 817C1DFC4343
		$a_01_2 = {38 00 31 00 46 00 39 00 38 00 35 00 43 00 30 00 38 00 35 00 43 00 30 00 } //1 81F985C085C0
		$a_01_3 = {34 00 30 00 33 00 31 00 43 00 31 00 } //1 4031C1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule VirTool_Win32_VBInject_AEB_2{
	meta:
		description = "VirTool:Win32/VBInject.AEB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 00 30 00 33 00 31 00 43 00 31 00 38 00 31 00 46 00 39 00 38 00 39 00 44 00 38 00 38 00 39 00 44 00 38 00 37 00 35 00 43 00 45 00 } //1 4031C181F989D889D875CE
		$a_01_1 = {34 00 33 00 34 00 33 00 38 00 33 00 43 00 33 00 30 00 32 00 38 00 31 00 37 00 43 00 31 00 44 00 46 00 43 00 34 00 45 00 34 00 45 00 } //1 434383C302817C1DFC4E4E
		$a_01_2 = {38 00 42 00 35 00 34 00 31 00 44 00 30 00 30 00 36 00 36 00 30 00 46 00 46 00 } //1 8B541D00660FF
		$a_03_3 = {ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 90 09 09 00 68 ?? ?? ?? 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule VirTool_Win32_VBInject_AEB_3{
	meta:
		description = "VirTool:Win32/VBInject.AEB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8d 4d ?? e8 ?? ?? ?? ff ff 75 ?? 68 ?? ?? ?? 00 90 09 09 00 68 ?? ?? ?? 00 e8 } //1
		$a_03_1 = {ff 8b d0 8b 4d ?? e8 ?? ?? ?? ff 8b 45 ?? ff 30 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8b 4d 0c e8 ?? ?? ?? ff 8b 45 ?? ff 30 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b d0 8b 4d ?? e8 ?? ?? ?? ff 8b 45 ?? ff 30 68 ?? ?? ?? 00 90 09 09 00 68 ?? ?? ?? 00 e8 } //1
		$a_01_2 = {34 00 30 00 33 00 31 00 43 00 31 00 } //1 4031C1
		$a_01_3 = {34 00 33 00 34 00 33 00 38 00 33 00 43 00 33 00 30 00 32 00 38 00 31 00 37 00 43 00 31 00 44 00 } //1 434383C302817C1D
		$a_01_4 = {38 00 42 00 35 00 34 00 31 00 44 00 30 00 30 00 } //1 8B541D00
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}