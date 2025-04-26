
rule Backdoor_Win32_Pedryak_A_dll{
	meta:
		description = "Backdoor:Win32/Pedryak.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {05 04 fc ff ff 3d c8 00 00 00 0f 87 ?? 00 00 00 33 c9 8a 88 ?? ?? 00 10 ff 24 8d ?? ?? 00 10 e8 ?? ?? 00 00 c3 } //3
		$a_03_1 = {3d 64 23 00 00 7f ?? ?? ?? 3d 14 05 00 00 7f } //3
		$a_03_2 = {8b 30 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 ff 15 ?? ?? 00 10 39 44 24 1c 75 0d 68 e0 93 04 00 ff 15 ?? ?? 00 10 eb bc b9 } //2
		$a_01_3 = {83 f8 33 7f 0c 8a c8 80 c1 47 88 0e 83 f8 33 7e 0c 83 f8 3e 7d 0a } //1
		$a_01_4 = {6e 65 74 6d 61 6e 2e 64 6c 6c 00 } //1
		$a_01_5 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 25 73 } //1 Accept-Language: %s
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}