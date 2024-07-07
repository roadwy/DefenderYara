
rule Trojan_Win32_TrickBot_PVK_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.PVK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 02 8b 4d fc 03 4d f8 81 e1 ff 00 00 00 33 d2 8a 94 0d 14 fd ff ff 33 c2 8b 4d 08 03 4d ec 88 01 } //2
		$a_01_1 = {8a 0c 11 8b 54 24 2c 8b 5c 24 04 32 0c 1a 66 89 44 24 3e 8b 54 24 28 88 0c 1a 83 c3 01 8b 4c 24 38 } //2
		$a_01_2 = {8a 3c 11 0f b6 cb 01 f9 21 f1 8b 74 24 34 32 3c 0e 8a 5c 24 2f 88 5c 24 61 8b 4c 24 24 88 3c 11 } //2
		$a_01_3 = {8b 55 fc 81 ea 00 10 00 00 89 55 fc 8b 45 08 33 45 0c 89 45 08 8b 4d fc c1 e1 03 89 4d fc } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=2
 
}