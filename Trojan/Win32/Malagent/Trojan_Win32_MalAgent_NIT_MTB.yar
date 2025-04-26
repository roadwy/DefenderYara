
rule Trojan_Win32_MalAgent_NIT_MTB{
	meta:
		description = "Trojan:Win32/MalAgent.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 85 d0 fd ff ff 2c 02 00 00 e8 48 06 00 00 8b f0 83 fe ff 75 11 33 c0 5e 8b 4d fc 33 cd e8 7f 06 00 00 8b e5 5d c3 57 8d 85 d0 fd ff ff 50 56 e8 28 06 00 00 85 c0 74 4f 8b 7d 08 8b c7 8d 8d f4 fd ff ff 0f 1f 40 00 66 8b 11 66 3b 10 75 1e 66 85 d2 74 15 66 8b 51 02 66 3b 50 02 75 0f 83 c1 04 83 c0 04 66 85 d2 75 de 33 c0 eb 05 1b c0 83 c8 01 85 c0 74 2a 8d 85 d0 fd ff ff 50 56 e8 df 05 00 00 85 c0 75 b4 } //2
		$a_01_1 = {ff 15 04 c0 44 00 85 c0 75 36 50 50 8d 85 54 fd ff ff 50 6a 00 68 40 c2 44 00 ff b5 50 fd ff ff ff 15 00 c0 44 00 ff b5 50 fd ff ff 8b f0 ff 15 08 c0 44 00 85 f6 74 31 81 fe ea 00 00 00 74 29 6a 00 68 7c c2 44 00 e8 eb be 00 00 83 c4 08 83 f8 ff 74 15 6a 00 6a 00 6a 00 68 80 11 40 00 6a 00 6a 00 ff 15 18 c0 44 00 68 f1 c1 44 00 } //2
		$a_01_2 = {7a 69 6c 69 61 6f 2e 6a 70 67 } //1 ziliao.jpg
		$a_01_3 = {63 68 75 61 6e 67 6b 6f 75 2e 6c 6f 67 } //1 chuangkou.log
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}