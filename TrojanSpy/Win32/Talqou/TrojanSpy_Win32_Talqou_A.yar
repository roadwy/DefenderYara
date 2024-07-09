
rule TrojanSpy_Win32_Talqou_A{
	meta:
		description = "TrojanSpy:Win32/Talqou.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 12 0f b6 11 33 c2 69 c0 ?? ?? 00 01 41 ff 4c 24 04 75 ee c3 } //1
		$a_01_1 = {8d 45 fc 50 ff 75 fc 2b fe 6a 05 83 ef 05 56 c6 06 e9 89 7e 01 ff 15 } //1
		$a_03_2 = {8b 4d 0c 8d 1c c1 8b 4d 08 8b 3c c1 8b 74 c1 04 0f cf 0f ce c7 45 fc ?? ?? ?? ?? c7 45 f4 20 00 00 00 ff 75 10 ff 75 fc 57 6a 0b 59 e8 d6 fe ff ff } //1
		$a_03_3 = {81 ec 8c 00 00 00 83 4d fc ff ?? 8b 5e 3c ?? 8b 7c 33 78 03 fe 8b 47 20 8b 4f 18 03 c6 89 45 f4 89 4d f8 85 c9 75 09 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}