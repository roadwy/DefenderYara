
rule Trojan_Win32_Esendi_D{
	meta:
		description = "Trojan:Win32/Esendi.D,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 06 00 00 "
		
	strings :
		$a_03_0 = {56 33 f6 46 eb 29 8b 0c b5 90 01 04 8d 04 b5 90 01 04 50 ff 30 8d 82 90 01 04 51 50 ff 15 90 01 04 8b 14 b5 90 01 04 8d 76 03 90 00 } //20
		$a_03_1 = {80 fb 21 8b c2 0f 45 c1 42 8b c8 8a 1a 84 db 90 01 02 85 c9 90 01 02 8d 41 01 90 00 } //10
		$a_00_2 = {3c 20 74 14 8b ca 0f be c0 83 c9 01 46 0f af c8 03 d1 } //10
		$a_00_3 = {8d 57 04 8b 0a 33 c8 81 e1 ff ff ff 7f 33 c8 8b c1 24 01 0f b6 c0 f7 d8 1b c0 d1 e9 25 df b0 08 99 33 87 34 06 00 00 33 c1 } //10
		$a_00_4 = {8d 57 04 8b 0a 33 c8 81 e1 ff ff ff 7f 33 c8 8b c1 24 01 0f b6 c0 f7 d8 1b c0 d1 e9 25 df b0 08 99 33 87 b4 f2 ff ff 33 c1 89 87 40 f6 ff ff 8d 3a 8b 02 83 eb 01 } //10
		$a_00_5 = {8b 8e 80 13 00 00 33 4e 04 81 e1 ff ff ff 7f 33 8e 80 13 00 00 8b c1 24 01 0f b6 c0 f7 d8 5f 1b c0 d1 e9 25 df b0 08 99 33 86 34 06 00 00 33 c1 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10) >=50
 
}