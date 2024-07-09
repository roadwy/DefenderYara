
rule TrojanDropper_Win32_Daws_B{
	meta:
		description = "TrojanDropper:Win32/Daws.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {6e 73 65 6e 74 70 72 66 2e 64 6c 6c 00 } //1
		$a_01_1 = {5c 66 61 6b 65 2e 62 61 74 00 } //1
		$a_01_2 = {2d 74 73 68 61 63 6b 00 } //1 琭桳捡k
		$a_01_3 = {2c 50 72 6f 78 79 44 6c 6c 00 } //1 倬潲祸汄l
		$a_01_4 = {53 45 54 44 4c 4c 5f 58 36 34 00 } //1
		$a_01_5 = {4e 54 43 4f 4f 4c 00 } //1
		$a_03_6 = {b8 4d 5a 00 00 8b 9d 54 ff ff ff 0f b7 0b 3b c8 75 1e db 05 ?? ?? ?? ?? 8b 9d 50 ff ff ff 8b 03 e8 ?? ?? ?? ?? de d9 df e0 9e 0f 84 05 00 00 00 e9 ?? ?? ?? ?? 6a 00 31 c0 8b dc 53 89 03 8b c7 50 ff 15 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*5) >=10
 
}