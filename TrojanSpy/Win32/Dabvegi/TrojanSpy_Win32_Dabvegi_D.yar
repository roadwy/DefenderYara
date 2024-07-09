
rule TrojanSpy_Win32_Dabvegi_D{
	meta:
		description = "TrojanSpy:Win32/Dabvegi.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 bd 74 ff ff ff (89 13|e9 03) 00 00 73 0c c7 85 } //1
		$a_03_1 = {80 e1 7f 66 0f b6 c9 66 6b c9 02 0f 80 ?? 07 00 00 (34|80 f2) 1b 66 33 ?? 8a ?? 33 ?? eb } //1
		$a_03_2 = {6a 00 68 00 00 00 80 6a 00 6a 00 8b 45 08 8b 08 51 8d 55 b8 52 ff 15 ?? ?? 40 00 50 8b 45 ?? 50 e8 ?? ?? ?? ff 89 45 ac } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}