
rule Trojan_Win64_Trickbot_A_mod{
	meta:
		description = "Trojan:Win64/Trickbot.A!mod,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 4c ?? ?? b8 09 04 02 81 83 e9 ?? 44 6b c1 ?? 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 b8 09 04 02 81 41 83 c0 7f 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 46 88 44 ?? ?? 49 ff ?? 49 83 ?? ?? 72 ab } //1
		$a_01_1 = {72 64 70 73 63 61 6e 2e 64 6c 6c 00 43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}