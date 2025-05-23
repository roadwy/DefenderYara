
rule TrojanSpy_Win32_Usteal_gen_A{
	meta:
		description = "TrojanSpy:Win32/Usteal.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {55 46 52 20 53 74 65 61 6c 65 72 20 52 65 70 6f 72 74 } //1 UFR Stealer Report
		$a_00_1 = {25 30 32 68 75 2d 25 30 32 68 75 2d 25 68 75 5f 25 30 32 68 75 2d 25 30 32 68 75 2d 25 30 32 68 75 } //1 %02hu-%02hu-%hu_%02hu-%02hu-%02hu
		$a_03_2 = {8d 74 13 0d 0f bf 3e 83 c6 02 60 57 56 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 61 0f bf 05 ?? ?? ?? ?? 66 3d 49 43 0f 85 ?? ?? 00 00 03 f7 0f be 06 8d 74 30 01 0f be 3e } //2
		$a_03_3 = {80 04 08 fb 40 3b c7 72 ?? 60 ff 75 e4 6a 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 61 e9 ?? ?? 00 00 66 3d 4a 41 0f 85 } //2
		$a_03_4 = {81 fb a7 81 00 00 74 18 81 fb a6 81 00 00 74 10 81 fb 79 81 00 00 74 08 81 fb 59 81 00 00 75 0c 60 e8 ?? ?? ?? ?? 61 eb 03 83 c6 0c 49 75 } //2
		$a_01_5 = {74 15 8b c8 33 d2 8b 75 08 8b fe ac 02 c2 f6 d0 fe c8 aa 42 49 75 f4 } //2
		$a_03_6 = {ac 84 c0 74 05 41 3b cb 75 f6 83 e9 02 8d 35 ?? ?? ?? ?? 8d 3d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 32 15 ?? ?? ?? ?? 80 ca ?? ac 32 c2 aa 49 75 f9 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2+(#a_01_5  & 1)*2+(#a_03_6  & 1)*2) >=6
 
}