
rule Trojan_Win32_Matsnu_gen_A{
	meta:
		description = "Trojan:Win32/Matsnu.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {5c 6e 74 6c 66 c7 85 ?? ?? ff ff 64 72 } //2
		$a_01_1 = {8b 75 08 83 c6 18 8b 4d 0c 83 e9 18 72 72 57 51 56 e8 } //2
		$a_01_2 = {63 6d 64 3d 6b 65 79 26 64 61 74 61 3d 25 75 3a 25 75 3a 25 73 } //1 cmd=key&data=%u:%u:%s
		$a_01_3 = {47 45 4f 3a 00 4c 4f 43 4b 3a 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}