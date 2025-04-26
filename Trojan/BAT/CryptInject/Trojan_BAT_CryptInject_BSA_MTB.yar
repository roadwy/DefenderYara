
rule Trojan_BAT_CryptInject_BSA_MTB{
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