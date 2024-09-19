
rule Trojan_Win32_Zenpak_ASAN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 0d } //2
		$a_01_1 = {0f b6 c0 83 c4 04 } //2
		$a_01_2 = {8a 4d fe 30 c8 a2 } //1
		$a_03_3 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 88 0d ?? ?? ?? 10 88 45 fb 88 4d fa 8a 45 fb 8a 4d fa 30 c8 8a 55 fb 88 15 ?? ?? ?? 10 a2 } //3
		$a_03_4 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 88 0d ?? ?? ?? 10 88 c2 30 ca a2 } //3
		$a_01_5 = {0f b6 c0 83 c4 04 5e 5d c3 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*3+(#a_03_4  & 1)*3+(#a_01_5  & 1)*2) >=5
 
}