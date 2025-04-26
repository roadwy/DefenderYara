
rule TrojanDropper_Win32_Meteit_D{
	meta:
		description = "TrojanDropper:Win32/Meteit.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 04 33 c0 8a 0a 84 c9 74 ?? 6b c0 1f 0f be c9 03 c1 42 } //1
		$a_01_1 = {8b 48 04 ff 45 08 83 e9 08 42 d1 e9 42 39 4d 08 72 } //2
		$a_03_2 = {8b 46 08 8b 4d 08 8b 04 88 83 f8 ff 74 ?? 50 ff 57 08 } //1
		$a_01_3 = {2b c8 b8 ab aa aa 2a f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}