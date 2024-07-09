
rule TrojanSpy_Win32_Wagiclas_B{
	meta:
		description = "TrojanSpy:Win32/Wagiclas.B,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 08 00 00 "
		
	strings :
		$a_03_0 = {0f b7 fb 8b 55 00 8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f ?? ?? ?? ?? 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 } //5
		$a_03_1 = {c1 e2 06 03 c2 33 d2 8a 53 02 0f b6 92 ?? ?? ?? 00 c1 e2 0c 03 c2 33 d2 8a 53 03 0f b6 92 ?? ?? ?? 00 c1 e2 12 } //5
		$a_00_2 = {47 6c 68 6b 6c 61 73 4b 66 7a } //1 GlhklasKfz
		$a_00_3 = {64 78 35 45 46 4f 57 6f 43 65 61 4f 4f 5a 56 37 32 42 } //1 dx5EFOWoCeaOOZV72B
		$a_00_4 = {53 41 31 6c 61 48 70 66 55 32 4f 4f } //1 SA1laHpfU2OO
		$a_00_5 = {45 6b 4d 77 71 58 47 59 56 38 4e } //1 EkMwqXGYV8N
		$a_00_6 = {50 70 71 43 32 34 78 49 65 45 47 64 57 44 } //1 PpqC24xIeEGdWD
		$a_00_7 = {46 46 47 6a 69 66 33 31 } //1 FFGjif31
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=12
 
}