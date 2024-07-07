
rule VirTool_Win32_VBInject_BI{
	meta:
		description = "VirTool:Win32/VBInject.BI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 8b d7 66 c1 fa 0f 66 8b da 33 55 ac 66 33 d9 66 3b da 7f 39 0f bf d9 3b de 72 05 } //1
		$a_03_1 = {50 45 00 00 0f 85 90 01 02 00 00 8b 45 10 6a 44 5b ff 30 89 9d 4c fd ff ff 90 00 } //1
		$a_03_2 = {6a 33 f3 ab 59 8d bd 90 01 02 ff ff f3 ab 6a 11 8d bd 90 01 02 ff ff 59 33 f6 f3 ab 8d bd 90 01 02 ff ff 6a 0c ab 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}