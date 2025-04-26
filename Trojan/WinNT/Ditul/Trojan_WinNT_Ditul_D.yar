
rule Trojan_WinNT_Ditul_D{
	meta:
		description = "Trojan:WinNT/Ditul.D,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_01_0 = {50 73 53 65 74 43 72 65 61 74 65 50 72 6f 63 65 73 73 4e 6f 74 69 66 79 52 6f 75 74 69 6e 65 } //1 PsSetCreateProcessNotifyRoutine
		$a_01_1 = {81 c3 ec 01 00 00 eb 2d 66 83 ff 03 75 25 } //2
		$a_01_2 = {01 00 00 6a 40 68 00 10 00 00 8d 45 f8 50 6a 00 8d 45 d8 50 ff 75 d4 ff 15 } //2
		$a_01_3 = {00 10 8b 42 0c 8d 14 24 cd 2e 83 c4 14 89 45 e0 83 7d e0 00 0f 8c } //2
		$a_01_4 = {00 10 8b 42 04 8d 14 24 cd 2e 83 c4 14 89 45 e0 83 7d e0 00 7c } //2
		$a_03_5 = {6a 0a 8d 46 04 50 ff 76 1c e8 ?? ?? ff ff 8d 45 e8 50 8d 45 c4 50 ff 76 14 8d 46 10 50 ff 15 } //3
		$a_01_6 = {8b 06 8b 09 8d 3c 81 57 c7 45 fc 20 00 00 00 ff d3 84 c0 74 } //3
		$a_01_7 = {89 1f 0f 20 c0 0d 00 00 01 00 0f 22 c0 8b 7d 0c 8b 45 fc 8b 75 f4 } //4
		$a_01_8 = {74 61 8b 1f 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 46 1c 6a 0a } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_03_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*4+(#a_01_8  & 1)*5) >=17
 
}