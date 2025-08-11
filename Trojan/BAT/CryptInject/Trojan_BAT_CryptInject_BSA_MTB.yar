
rule Trojan_BAT_CryptInject_BSA_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 9d a2 1d 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 37 00 00 00 12 00 } //10
		$a_01_1 = {48 61 6c 6c 61 6a 2e 50 72 6f 70 65 72 74 69 65 73 } //10 Hallaj.Properties
		$a_01_2 = {6c 6f 76 65 72 2e 65 78 65 } //9 lover.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*9) >=29
 
}
rule Trojan_BAT_CryptInject_BSA_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 6d 65 63 64 2e 65 78 65 00 41 6d 65 63 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4d 65 6d 62 65 72 52 65 66 73 50 72 6f 78 79 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 6f 75 73 65 4f 66 43 } //13
		$a_01_1 = {32 62 37 33 63 35 31 63 2d 39 64 35 33 2d 34 61 34 30 2d 38 32 36 39 2d 61 35 33 34 37 38 66 61 31 36 64 34 } //10 2b73c51c-9d53-4a40-8269-a53478fa16d4
	condition:
		((#a_03_0  & 1)*13+(#a_01_1  & 1)*10) >=23
 
}
rule Trojan_BAT_CryptInject_BSA_MTB_3{
	meta:
		description = "Trojan:BAT/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 04 00 00 "
		
	strings :
		$a_01_0 = {d0 3b 00 00 01 2b 17 7e 71 00 00 04 20 56 c0 66 06 2b 12 2b 17 2b 1c 2b 1d 2b 22 2b 27 2a } //10
		$a_01_1 = {2b e2 02 2b e1 28 43 00 00 0a 2b dc 28 01 00 00 2b 2b d7 6f 45 00 00 0a 2b d2 } //10
		$a_01_2 = {4d 65 6d 62 65 72 52 65 66 73 50 72 6f 78 79 } //9 MemberRefsProxy
		$a_01_3 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //9 SmartAssembly.HouseOfCards
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*9+(#a_01_3  & 1)*9) >=38
 
}
rule Trojan_BAT_CryptInject_BSA_MTB_4{
	meta:
		description = "Trojan:BAT/CryptInject.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 08 00 00 "
		
	strings :
		$a_01_0 = {72 17 01 00 70 28 05 00 00 0a 6f 09 00 00 0a } //5
		$a_01_1 = {72 83 01 00 70 28 05 00 00 0a 6f 09 00 00 0a 80 1e 00 00 04 } //5
		$a_01_2 = {08 07 17 73 22 00 00 0a 0d 09 02 16 02 8e 69 6f 23 00 00 0a } //3
		$a_01_3 = {09 2c 06 09 6f 26 00 00 0a dc 08 2c 06 08 6f } //2
		$a_81_4 = {56 32 39 33 4e 6a 52 54 5a 58 52 55 61 48 4a 6c 59 57 52 44 62 32 35 30 5a 58 68 30 } //2 V293NjRTZXRUaHJlYWRDb250ZXh0
		$a_81_5 = {55 32 56 30 56 47 68 79 5a 57 46 6b 51 32 39 75 64 47 56 34 64 41 3d 3d } //2 U2V0VGhyZWFkQ29udGV4dA==
		$a_81_6 = {56 6d 6c 79 64 48 56 68 62 45 46 73 62 47 39 6a 52 58 67 } //2 VmlydHVhbEFsbG9jRXg
		$a_81_7 = {57 6e 64 56 62 6d 31 68 63 46 5a 70 5a 58 64 50 5a 31 4e 31 59 33 52 70 62 32 34 3d } //2 WndVbm1hcFZpZXdPZ1N1Y3Rpb24=
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2) >=23
 
}