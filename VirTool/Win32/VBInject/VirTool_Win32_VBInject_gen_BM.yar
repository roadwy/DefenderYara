
rule VirTool_Win32_VBInject_gen_BM{
	meta:
		description = "VirTool:Win32/VBInject.gen!BM,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 64 52 43 34 00 } //1
		$a_01_1 = {6d 6f 64 49 6e 6a 65 63 74 00 } //2 潭䥤橮捥t
		$a_01_2 = {6d 6f 64 41 6e 74 69 56 4d 00 } //2 潭䅤瑮噩M
		$a_03_3 = {6a 53 50 ff d6 8d 8d ?? ?? ff ff 6a 65 51 ff d6 8d 95 ?? ?? ff ff 6a 72 } //1
		$a_03_4 = {6a 52 51 ff d6 8d 95 ?? ?? ff ff 6a 45 52 ff d6 8d 85 ?? ?? ff ff 6a 2a } //2
		$a_03_5 = {6a 42 52 ff d6 8d 85 ?? ?? ff ff 6a 4f 50 ff d6 8d 8d ?? ?? ff ff 6a 58 51 ff d6 8d 95 ?? ?? ff ff 6a 2a } //3
		$a_03_6 = {6a 04 51 56 c7 45 ?? 58 59 59 59 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*3+(#a_03_6  & 1)*1) >=6
 
}