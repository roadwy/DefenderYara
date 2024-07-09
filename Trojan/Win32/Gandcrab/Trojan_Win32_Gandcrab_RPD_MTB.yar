
rule Trojan_Win32_Gandcrab_RPD_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 69 70 69 77 65 74 65 77 61 76 61 73 61 20 25 73 } //1 cipiwetewavasa %s
		$a_01_1 = {6c 6f 67 65 6a 75 78 6f 73 69 64 69 6a 6f 68 61 72 75 78 61 79 6f 67 6f 72 61 20 79 6f 63 69 63 65 6e 65 68 6f 7a 6f 67 6f 6c 65 68 65 6a 6f 73 61 7a 6f 62 69 20 6c 6f 6e 6f 7a 69 77 6f 76 61 7a 65 66 61 62 6f 66 61 76 69 73 65 66 75 20 6e 6f 74 75 64 6f 20 76 6f 7a 61 77 65 73 6f 6a 69 6d 65 74 61 73 75 6a 69 6e 65 66 65 67 65 63 69 70 61 6e 6f 6c 75 20 79 69 66 6f 7a 6f 62 65 72 69 20 66 65 7a 69 64 61 77 61 20 7a 75 67 65 6e 69 79 6f 6b 75 6c 75 79 65 73 65 70 75 68 65 7a 69 6d 6f 73 61 66 6f } //1 logejuxosidijoharuxayogora yocicenehozogolehejosazobi lonoziwovazefabofavisefu notudo vozawesojimetasujinefegecipanolu yifozoberi fezidawa zugeniyokuluyesepuhezimosafo
		$a_02_2 = {30 04 1f 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 33 c0 89 b5 e8 f7 ff ff 8d bd ec f7 ff ff ab 8d 85 e8 f7 ff ff 50 56 56 56 ff 15 ?? ?? ?? ?? 8d 85 f4 f7 ff ff 50 56 ff 15 ?? ?? ?? ?? 43 3b 5d } //2
		$a_02_3 = {8a e3 8a c3 80 e3 f0 c0 e0 06 0a 44 3a ?? 80 e4 fc c0 e3 02 0a 1c 3a c0 e4 04 0a 64 3a ?? 83 c7 04 88 1c 31 88 64 31 01 88 44 31 02 83 c1 03 3b 7d 00 72 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}