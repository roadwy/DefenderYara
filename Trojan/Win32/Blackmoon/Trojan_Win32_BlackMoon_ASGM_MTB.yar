
rule Trojan_Win32_BlackMoon_ASGM_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.ASGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 b6 bc d2 00 68 00 00 00 00 68 01 20 00 00 ff 75 ec ff 15 } //2
		$a_01_1 = {89 45 f0 ff 75 f8 68 00 00 00 00 ff 75 f0 8b 5d 08 ff 33 ff 15 } //2
		$a_01_2 = {89 45 ec 68 80 a0 80 00 68 00 00 00 00 68 09 04 00 00 ff 75 ec ff 15 } //1
		$a_01_3 = {62 38 36 39 37 30 36 62 34 32 66 30 63 32 30 32 65 35 36 36 37 66 32 32 64 61 31 63 39 63 66 35 } //1 b869706b42f0c202e5667f22da1c9cf5
		$a_01_4 = {63 33 5c 6e 70 63 5c 37 34 34 5c 31 30 30 2e 63 33 } //1 c3\npc\744\100.c3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}