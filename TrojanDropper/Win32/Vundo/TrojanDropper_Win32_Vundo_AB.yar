
rule TrojanDropper_Win32_Vundo_AB{
	meta:
		description = "TrojanDropper:Win32/Vundo.AB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {f7 f3 0f b7 44 15 ?? 03 c1 33 d2 f7 b5 ?? ff ff ff 8a 04 3e 8b ca 8a 14 39 88 14 3e 46 88 04 39 3b b5 ?? ff ff ff 72 cd ff 45 ?? 83 7d ?? 64 72 b8 } //1
		$a_03_1 = {81 ff 75 61 6c 41 75 ?? 81 fb 6c 6c 6f 63 } //1
		$a_03_2 = {81 ff 75 61 6c 51 75 ?? 81 fb 75 65 72 79 } //1
		$a_03_3 = {81 ff 75 61 6c 46 75 ?? 81 fb 72 65 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}