
rule Trojan_Win32_Zusy_NIT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 e8 dc 62 00 ff 15 2c 62 46 00 8b 54 24 20 8b 42 20 50 ff 15 20 62 46 00 8b 4c 24 20 6a 00 6a 14 8b 51 28 52 ff 15 24 62 46 00 5f 5e 5d b8 01 00 00 00 5b 83 c4 08 } //2
		$a_01_1 = {51 a1 10 d8 62 00 33 d2 3b c2 75 1a 33 c0 88 80 10 d7 62 00 40 3d 00 01 00 00 7c f2 c7 05 10 d8 62 00 01 00 00 00 8b 44 24 0c 53 8b 5c 24 14 } //2
		$a_01_2 = {50 ff 15 ac 63 46 00 85 c0 0f 84 b4 00 00 00 a1 60 dc 62 00 25 ff ff 00 00 50 ff 15 d4 63 46 00 8b f0 85 f6 75 10 ff 15 f8 63 46 00 5f } //2
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 57 33 32 54 69 6d 65 } //1 Software\Microsoft\Windows\CurrentVersion\Run\W32Time
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}