
rule Backdoor_Win32_Zegost_S{
	meta:
		description = "Backdoor:Win32/Zegost.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_10_0 = {56 65 72 43 68 6b 3d 25 64 3a 45 4e 44 7c 25 73 } //1 VerChk=%d:END|%s
		$a_10_1 = {25 73 2c 43 6c 65 61 72 53 65 6c 66 20 25 73 } //1 %s,ClearSelf %s
		$a_03_2 = {ff ff 83 fa 53 0f 85 ?? ?? 00 00 0f be 85 ?? ?? ff ff 83 f8 50 0f 85 ?? ?? 00 00 0f be 8d ?? ?? ff ff 83 f9 36 0f 85 ?? ?? 00 00 c6 85 64 ?? ?? ff 53 } //2
		$a_03_3 = {68 04 01 00 00 ff 15 ?? ?? ?? ?? c6 45 f8 25 c6 45 f9 73 c6 45 fa 5c c6 45 fb 25 c6 45 fc 64 c6 45 fd 00 } //2
	condition:
		((#a_10_0  & 1)*1+(#a_10_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=3
 
}
rule Backdoor_Win32_Zegost_S_2{
	meta:
		description = "Backdoor:Win32/Zegost.S,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 75 70 64 61 74 65 5c 48 6c 49 6e 69 74 2e 64 61 74 } //1 \update\HlInit.dat
		$a_00_1 = {5c 50 6c 75 67 69 6e 5c cb ab bf aa 33 33 38 39 2e 65 78 65 } //1
		$a_00_2 = {43 47 68 30 73 74 56 69 65 77 } //1 CGh0stView
		$a_00_3 = {b1 e4 d2 ec 43 43 20 bf c9 d2 d4 d3 d0 } //1
		$a_00_4 = {74 65 6e 63 65 6e 74 3a 2f 2f 6d 65 73 73 61 67 65 2f 3f 75 69 6e 3d 32 34 33 31 30 37 26 53 69 74 65 3d 32 34 33 31 30 37 26 4d 65 6e 75 3d 79 65 73 } //1 tencent://message/?uin=243107&Site=243107&Menu=yes
		$a_01_5 = {8a 1c 11 80 c3 7a 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 19 88 1c 11 41 3b c8 7c e1 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*2) >=4
 
}