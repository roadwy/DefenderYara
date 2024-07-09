
rule TrojanDropper_Win32_Brackash_gen_B{
	meta:
		description = "TrojanDropper:Win32/Brackash.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {75 7f 83 7b 04 00 7e 79 8d 55 fc 8b 43 04 e8 ?? ?? ff ff 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? f8 ff 85 c0 7e 34 } //10
		$a_03_1 = {84 c0 75 3f 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? f9 ff 8b f0 8d 45 ec b9 ?? ?? ?? ?? 8b 55 fc e8 ?? ?? f8 ff 8b 55 ec 8b c6 e8 ?? ?? f9 ff 8b c6 e8 ?? ?? f8 ff 8d 45 e8 b9 ?? ?? ?? ?? 8b 55 fc e8 ?? ?? f8 ff 8b 45 e8 e8 ?? ?? f8 ff 84 c0 75 3f } //10
		$a_03_2 = {7a 71 64 62 (31|32) 2e 64 6c 6c 00 } //2
		$a_03_3 = {6d 79 64 6c 6c (31|32) 00 } //2
		$a_03_4 = {72 61 6e 64 6f 6d 66 75 6e 63 69 6f 6e 64 69 72 6d 65 6d 6f 72 79 (6c 69 6b 65|68 61 74 65) 00 } //2
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2) >=12
 
}