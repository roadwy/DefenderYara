
rule TrojanSpy_Win32_Karnos_A{
	meta:
		description = "TrojanSpy:Win32/Karnos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {f3 a6 0f 84 ?? ?? ?? ?? b9 0a 00 00 00 8d 7c 24 ?? f3 ab 66 ab b9 0a 00 00 00 8b ?? 8d 7c 24 ?? 68 ?? ?? ?? ?? f3 a5 66 a5 8b 35 ?? ?? ?? ?? 8d 4c 24 ?? 51 ff d6 85 c0 74 } //1
		$a_02_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 35 31 77 61 6e 61 2e 63 6f 6d 2f 74 6a 2f 73 65 74 2e 61 73 70 00 00 00 00 73 3d 25 73 26 68 3d 25 64 00 00 00 68 74 74 70 3a 2f 2f 70 6c 75 67 69 6e 2e 39 32 74 61 6f 6a 69 6e 2e 63 6f 6d 2f 70 6c 75 67 69 6e 2f 61 63 63 65 70 74 2f 73 65 61 72 63 68 6c 6f 67 00 00 64 61 74 61 3d 25 73 00 7b 22 68 6f 73 74 22 3a 25 75 2c 22 6b 65 79 22 3a 22 25 73 22 2c 20 22 69 65 6e 61 6d 65 22 3a 22 [0-05] 22 7d } //1
		$a_00_2 = {62 69 6e 67 2e 63 6f 6d 00 00 00 00 67 6f 6f 67 6c 65 00 00 73 6f 67 6f 75 2e 63 6f 6d 00 00 00 73 6f 73 6f 2e 63 6f 6d 00 00 00 00 62 61 69 64 75 2e 63 6f 6d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}