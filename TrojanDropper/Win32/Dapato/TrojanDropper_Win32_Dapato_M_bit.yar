
rule TrojanDropper_Win32_Dapato_M_bit{
	meta:
		description = "TrojanDropper:Win32/Dapato.M!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 7c 0f 01 00 48 8d 49 01 75 f5 0f b7 ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 66 89 04 39 4d 8b c1 49 ff c0 42 80 3c 02 00 75 f6 49 ff c0 0f 1f 00 } //1
		$a_03_1 = {49 ff c0 42 80 3c 03 00 75 f6 49 83 c0 02 48 8d 4c 24 20 48 8b d3 e8 ?? ?? ?? ?? 33 d2 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 48 8b 8c 24 20 02 00 00 48 33 cc e8 ?? ?? ?? ?? 48 81 c4 30 02 00 00 5b c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}