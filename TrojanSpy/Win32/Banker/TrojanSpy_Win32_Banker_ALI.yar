
rule TrojanSpy_Win32_Banker_ALI{
	meta:
		description = "TrojanSpy:Win32/Banker.ALI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 03 0f b6 80 ?? ?? ?? ?? 33 d2 8a 53 01 0f b6 92 ?? ?? ?? ?? c1 e2 06 03 c2 33 d2 8a 53 02 0f b6 92 ?? ?? ?? ?? c1 e2 0c 03 c2 33 d2 8a 53 03 } //1
		$a_01_1 = {0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 } //1
		$a_00_2 = {6f 50 4c 76 71 67 47 50 43 6f 6a 64 6c 41 } //1 oPLvqgGPCojdlA
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}