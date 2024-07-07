
rule Trojan_Win32_starter_KA_MTB{
	meta:
		description = "Trojan:Win32/starter.KA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 8b 08 8a 54 29 03 8a c2 8a da 80 e2 f0 c0 e0 06 0a 44 29 02 80 e3 fc c0 e2 02 0a 14 29 c0 e3 04 0a 5c 29 01 83 c5 04 88 14 3e 88 5c 3e 01 88 44 3e 02 83 c6 03 8b 44 24 14 3b 28 72 bf } //2
		$a_01_1 = {8b 44 24 1c 03 44 24 14 33 c8 29 4c 24 10 b9 f7 ff ff ff 8b 44 24 28 2b c8 03 4c 24 1c 89 4c 24 1c ff 44 24 18 83 7c 24 18 20 72 80 8b 74 24 20 8b 5c 24 2c 8b 44 24 10 8b 6c 24 34 89 04 f3 8b 44 24 14 89 44 f3 04 46 89 74 24 20 3b 74 24 30 0f 82 11 ff ff ff } //2
		$a_01_2 = {6e 75 74 61 76 65 63 65 68 65 6e 75 62 65 70 75 68 75 67 75 77 75 6a 65 6a 69 78 61 66 75 2e 6a 70 67 } //1 nutavecehenubepuhuguwujejixafu.jpg
		$a_01_3 = {70 61 63 65 6c 75 6e 75 79 69 66 75 6e 6f 67 61 63 65 62 6f 72 61 2e 74 78 74 } //1 pacelunuyifunogacebora.txt
		$a_01_4 = {7a 75 6d 65 64 65 6c 6f 63 69 66 75 63 61 76 6f 78 69 6c 69 74 75 76 61 62 75 2e 74 78 74 } //1 zumedelocifucavoxilituvabu.txt
		$a_01_5 = {68 75 64 65 6a 69 74 61 66 65 70 69 6a 69 77 61 67 65 6b 75 77 69 2e 6a 70 67 } //1 hudejitafepijiwagekuwi.jpg
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}