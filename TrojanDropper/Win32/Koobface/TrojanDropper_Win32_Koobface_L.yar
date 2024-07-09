
rule TrojanDropper_Win32_Koobface_L{
	meta:
		description = "TrojanDropper:Win32/Koobface.L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 4d fc ff e8 24 00 00 00 83 7d e0 00 75 13 ff 75 08 6a 00 ff 35 ?? ?? 44 00 ff 15 64 ?? 41 00 8b f0 8b c6 } //1
		$a_03_1 = {ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 ?? ?? ?? ?? 8b f0 } //1
		$a_03_2 = {6a 1c 8d 45 d8 50 56 ff 15 1c ?? 41 00 85 c0 74 77 8b 5d dc 8d 45 b4 50 ff 15 5c ?? 41 00 8b 4d b8 a1 } //1
		$a_03_3 = {41 00 ff 25 68 ?? 41 00 ff 25 6c ?? 41 00 ff 25 70 ?? 41 00 ff 25 74 ?? 41 00 ff 25 78 ?? 41 00 ff 25 7c ?? 41 00 ff 25 80 ?? 41 00 ff 25 84 ?? 41 00 cc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}