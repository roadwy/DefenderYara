
rule Trojan_Win32_Wantvi_E{
	meta:
		description = "Trojan:Win32/Wantvi.E,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 ec ?? ?? 00 00 [0-0c] 68 04 01 00 00 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? 00 6a 1b 68 00 ?? ?? 00 68 00 ?? ?? 00 68 00 ?? ?? 00 8d 95 ?? ?? ff ff 52 } //10
		$a_02_1 = {5c 75 73 65 72 [0-01] 33 32 2e 64 61 74 } //10
		$a_00_2 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //10 GetSystemDirectoryA
		$a_00_3 = {62 6c 6a 61 68 61 20 6d 75 61 68 61 20 7a 61 69 6e 61 6c 6f 20 76 73 65 21 3d } //10 bljaha muaha zainalo vse!=
		$a_00_4 = {61 6c 6f 20 76 73 65 61 3d } //1 alo vsea=
		$a_00_5 = {2f 36 3a 61 6a 61 20 6d 71 61 67 61 } //1 /6:aja mqaga
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=41
 
}