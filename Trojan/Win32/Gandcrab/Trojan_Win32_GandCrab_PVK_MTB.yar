
rule Trojan_Win32_GandCrab_PVK_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 a3 90 01 04 81 05 90 01 04 c3 9e 26 00 0f b7 05 90 01 04 25 ff 7f 00 00 90 09 05 00 a1 90 00 } //1
		$a_02_1 = {8b 45 08 8d 0c 06 e8 90 01 04 30 01 46 3b f7 7c 90 00 } //1
		$a_02_2 = {8a 6c 38 03 8a cd 8a d5 80 e1 f0 c0 e5 06 0a 6c 38 02 80 e2 fc c0 e1 02 0a 0c 38 c0 e2 04 0a 54 38 01 81 3d 90 01 04 be 00 00 00 90 00 } //2
		$a_02_3 = {89 c1 8d 44 3f 03 83 e0 fc e8 90 01 04 89 d8 89 e3 83 e3 f0 89 dc 51 53 6a ff 50 6a 00 68 e9 fd 00 00 90 00 } //2
		$a_02_4 = {8a 5c 24 1f 8a 44 24 12 0a df 88 04 2e 81 3d 90 01 04 41 04 00 00 75 0a 90 00 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2) >=2
 
}