
rule VirTool_Win32_VBInject_WD{
	meta:
		description = "VirTool:Win32/VBInject.WD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b d0 8d 4d d4 ff d6 50 53 6a ff 68 20 01 00 00 ff 15 } //1
		$a_01_1 = {4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 32 00 4d 6f 64 75 6c 65 33 00 4d 6f 64 75 6c 65 34 00 4d 6f 64 75 6c 65 35 00 4d 6f 64 75 6c 65 36 00 } //1 潍畤敬1潍畤敬2潍畤敬3潍畤敬4潍畤敬5潍畤敬6
		$a_00_2 = {50 00 72 00 6f 00 6a 00 65 00 6b 00 74 00 31 00 } //1 Projekt1
		$a_00_3 = {45 00 78 00 65 00 63 00 75 00 74 00 61 00 62 00 6c 00 65 00 20 00 46 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 65 00 78 00 65 00 7c 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 20 00 46 00 69 00 6c 00 65 00 73 00 7c 00 2a 00 2e 00 6c 00 6e 00 6b 00 } //1 Executable Files|*.exe|Shortcut Files|*.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}