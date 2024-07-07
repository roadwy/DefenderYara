
rule VirTool_Win32_VBInject_ADI{
	meta:
		description = "VirTool:Win32/VBInject.ADI,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d be 00 f0 ff ff bb 00 10 00 00 50 54 6a 04 53 57 ff d5 8d 87 df 01 00 00 80 20 7f 80 60 28 7f 58 50 54 50 53 57 ff d5 58 61 8d 44 24 80 6a 00 } //1
		$a_01_1 = {8b 45 08 8b 00 ff 75 08 ff 50 08 8b 45 fc 8b 4d ec 64 89 0d 00 00 00 00 5f 5e 5b c9 c2 04 00 } //1
		$a_03_2 = {ff 15 00 43 6f 6d 63 74 6c 4c 69 62 2e 50 72 6f 67 72 65 73 73 42 61 72 00 03 90 01 08 0f 00 00 2d 4c 42 09 00 4c 00 00 00 21 43 34 12 08 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}