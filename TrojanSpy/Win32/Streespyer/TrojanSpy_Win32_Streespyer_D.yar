
rule TrojanSpy_Win32_Streespyer_D{
	meta:
		description = "TrojanSpy:Win32/Streespyer.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 00 57 00 6e 00 64 00 50 00 72 00 6f 00 63 00 50 00 74 00 72 00 30 00 30 00 34 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 31 00 } //1 FWndProcPtr0040000000000001
		$a_03_1 = {16 53 65 72 76 69 63 65 42 65 66 6f 72 65 55 6e 69 6e 73 74 61 6c 6c ?? ?? ?? ?? ?? ?? 18 4d 65 73 73 61 67 65 5f 54 65 63 6c 61 73 5f 64 65 5f 41 74 61 6c 68 6f 0a 54 52 70 63 4c 6f 6f 6b 75 70 } //1
		$a_01_2 = {8b 45 10 0f b6 00 8b 55 0c 0f b6 44 02 ff 8b 55 10 0f b6 52 01 8b 4d 0c 0f b6 54 11 ff 03 c2 8b 55 10 0f b6 52 02 8b 4d 0c 0f b6 54 11 ff 03 c2 89 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}