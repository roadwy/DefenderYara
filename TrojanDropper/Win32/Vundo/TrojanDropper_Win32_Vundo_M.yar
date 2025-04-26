
rule TrojanDropper_Win32_Vundo_M{
	meta:
		description = "TrojanDropper:Win32/Vundo.M,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_03_0 = {89 4d dc 8b f9 c1 e7 ?? c1 e9 ?? 0b cf 89 4d dc 0f b6 d2 2b ca e9 15 ff ff ff } //2
		$a_03_1 = {81 f9 0d 97 52 1d 0f 84 ?? ?? 00 00 } //1
		$a_03_2 = {81 f9 8d c7 87 28 0f 84 ?? ?? 00 00 } //1
		$a_03_3 = {81 f9 7f 49 ab d2 0f 84 ?? ?? 00 00 } //1
		$a_03_4 = {81 f9 39 b9 12 92 0f 84 ?? ?? 00 00 } //1
		$a_03_5 = {81 f9 02 9b 49 ab 0f 84 ?? ?? 00 00 } //1
		$a_03_6 = {81 f9 b3 f6 b6 4b 0f 84 ?? ?? 00 00 } //1
		$a_03_7 = {81 f9 0b aa 18 2f 0f 84 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1) >=3
 
}