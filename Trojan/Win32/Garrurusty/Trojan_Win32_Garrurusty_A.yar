
rule Trojan_Win32_Garrurusty_A{
	meta:
		description = "Trojan:Win32/Garrurusty.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c1 be 03 00 00 00 99 f7 fe 8a 04 29 80 c2 41 32 c2 88 04 29 41 3b cb 72 e6 } //10
		$a_01_1 = {44 00 72 00 57 00 61 00 74 00 73 00 6f 00 6e 00 2e 00 64 00 6c 00 6c 00 } //1 DrWatson.dll
		$a_01_2 = {44 00 72 00 57 00 61 00 74 00 73 00 6f 00 6e 00 2e 00 63 00 66 00 67 00 } //1 DrWatson.cfg
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}
rule Trojan_Win32_Garrurusty_A_2{
	meta:
		description = "Trojan:Win32/Garrurusty.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0c ff 2a 04 29 88 04 3a 8d 04 1a 99 f7 fe 41 3b ce 7c ed } //1
		$a_01_1 = {70 00 69 00 70 00 65 00 5c 00 4e 00 61 00 6e 00 6e 00 65 00 64 00 50 00 69 00 70 00 65 00 } //1 pipe\NannedPipe
		$a_01_2 = {68 20 bf 02 00 ff d7 83 fe 08 74 27 83 fe 05 74 22 83 fe 06 74 1d 83 fe 07 74 18 83 fe 04 75 e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Garrurusty_A_3{
	meta:
		description = "Trojan:Win32/Garrurusty.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f be c3 83 e8 49 89 55 f8 0f 84 a6 00 00 00 83 e8 09 0f 84 9d 00 00 00 48 0f 85 16 01 00 00 } //1
		$a_01_1 = {0f 84 6f 02 00 00 66 3b ce 75 0c 66 39 70 02 75 06 66 39 78 06 74 15 } //1
		$a_01_2 = {70 00 6c 00 75 00 74 00 6f 00 6e 00 69 00 75 00 6d 00 00 00 65 00 78 00 69 00 73 00 74 00 73 00 } //1
		$a_01_3 = {64 00 63 00 6f 00 6d 00 73 00 2e 00 64 00 6c 00 6c 00 } //1 dcoms.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Trojan_Win32_Garrurusty_A_4{
	meta:
		description = "Trojan:Win32/Garrurusty.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {0c ff 2a 04 29 88 04 3a 8d 04 1a 99 f7 fe 41 3b ce 7c ed } //10
		$a_01_1 = {3d 99 00 00 00 0f 84 f2 fa ff ff 3d 9a 00 00 00 0f 84 e7 fa ff ff 3d 85 00 00 00 75 1e } //10
		$a_01_2 = {57 00 65 00 62 00 4d 00 6f 00 6e 00 65 00 79 00 20 00 4b 00 65 00 65 00 70 00 65 00 72 00 20 00 43 00 6c 00 61 00 73 00 73 00 69 00 63 00 } //1 WebMoney Keeper Classic
		$a_01_3 = {78 69 61 6e 67 79 69 6e 2e 64 79 6e 64 6e 73 2d 77 65 62 2e 63 6f 6d } //1 xiangyin.dyndns-web.com
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=21
 
}