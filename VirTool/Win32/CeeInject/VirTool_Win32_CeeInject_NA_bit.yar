
rule VirTool_Win32_CeeInject_NA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.NA!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_03_1 = {46 69 6c 65 20 64 65 73 63 72 69 70 74 69 6f 6e 90 02 10 2e 65 78 65 90 00 } //1
		$a_01_2 = {61 63 74 69 6f 6e 3d 63 77 00 3f 61 63 74 69 6f 6e 3d 72 77 } //1 捡楴湯挽w愿瑣潩㵮睲
		$a_01_3 = {67 61 74 65 77 61 79 2e 70 68 70 } //1 gateway.php
		$a_01_4 = {8b 45 dc 8b 50 04 8b 45 dc 8b 40 08 89 c1 8b 45 d4 29 c1 89 c8 01 d0 83 e8 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}