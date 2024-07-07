
rule Trojan_Win32_Napolar_A{
	meta:
		description = "Trojan:Win32/Napolar.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 3d 25 64 2e 25 64 26 75 3d 25 73 26 63 3d 25 73 26 73 3d 25 73 26 77 3d 25 64 2e } //1 v=%d.%d&u=%s&c=%s&s=%s&w=%d.
		$a_03_1 = {8b 10 81 fa 50 45 00 00 0f 85 90 01 04 89 85 90 01 02 ff ff 8b 95 90 01 02 ff ff 8b 42 78 03 85 90 01 02 ff ff 89 85 90 01 02 ff ff 8b 50 18 4a 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Napolar_A_2{
	meta:
		description = "Trojan:Win32/Napolar.A,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 40 3c 99 03 04 24 13 54 24 04 83 c4 08 89 45 90 01 01 8b 45 90 02 10 2d 00 10 00 00 05 00 02 00 00 89 45 90 01 01 8b 45 90 01 01 8b 40 18 8b 55 90 01 01 2b 42 34 03 45 90 01 01 2d 00 10 00 00 05 00 02 00 00 89 45 90 01 01 6a 00 6a 01 6a 00 ff 55 90 00 } //10
		$a_00_1 = {05 75 4c 6f 63 6b 07 53 79 73 49 6e 69 74 06 53 79 73 74 65 6d 8d 40 00 00 00 00 00 } //10
		$a_03_2 = {8d 45 fc 50 6a 40 6a 06 68 a4 42 40 00 6a ff e8 90 01 04 3c 01 75 36 b8 a4 42 40 00 c6 00 68 b8 90 01 02 40 00 ba a4 42 40 00 42 89 02 b8 a4 42 40 00 83 c0 05 c6 00 c3 8d 45 fc 50 8b 45 fc 50 6a 06 68 a4 42 40 00 6a ff 90 00 } //10
		$a_01_3 = {50 6a 00 6a 00 68 03 80 00 00 8b 45 fc 50 } //1
		$a_01_4 = {8b 45 f8 40 25 ff 00 00 00 89 45 f8 8b 45 f8 8b 84 85 ec fb ff ff 03 45 f4 25 ff 00 00 00 89 45 f4 8b 45 f8 8a 84 85 ec fb ff ff 88 45 f3 8b 45 f4 8b 84 85 ec fb ff ff 8b 55 f8 89 84 95 ec fb ff ff 33 c0 8a 45 f3 8b 55 f4 89 84 95 ec fb ff ff 8b 45 f8 8b 84 85 ec fb ff ff 8b 55 f4 03 84 95 ec fb ff ff 25 ff 00 00 00 8a 84 85 ec fb ff ff 8b 55 08 03 55 fc 30 02 ff 45 fc ff 4d ec 0f 85 7b ff ff ff } //1
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=32
 
}