
rule Trojan_Win32_Wiessy_A{
	meta:
		description = "Trojan:Win32/Wiessy.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //5 SetThreadContext
		$a_00_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //5 WriteProcessMemory
		$a_00_2 = {5c 2a 73 74 2e 65 78 65 00 } //1
		$a_03_3 = {50 68 00 e0 00 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0 75 1c 83 c6 04 81 fe ?? ?? 41 00 0f 8c 49 ff ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 04 68 04 01 00 00 } //2
		$a_01_4 = {52 ff d6 85 c0 74 0a 81 7c 24 30 00 38 00 00 74 22 8d 44 24 10 } //2
		$a_03_5 = {f3 a5 66 81 7c 24 ?? 4d 5a 75 54 8b 44 24 ?? 8d 48 18 3b d9 72 49 8b 0d ?? ?? ?? 00 8d 1c 01 03 da 8b d3 8b 02 8b 4a 04 89 44 24 ?? 8b 42 08 } //1
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*2+(#a_03_5  & 1)*1) >=12
 
}