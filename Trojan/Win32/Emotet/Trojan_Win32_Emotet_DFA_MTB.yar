
rule Trojan_Win32_Emotet_DFA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 45 0c 0f b6 94 15 90 01 04 03 c2 8b 4d 10 99 f7 ff 8b bd 90 01 04 8a 84 15 90 1b 00 30 04 0f 90 00 } //01 00 
		$a_02_1 = {33 d2 40 b9 8e 0a 00 00 f7 f1 6a 00 6a 00 8b fa 33 d2 89 7d 08 8a 84 3d 90 01 04 0f b6 c8 88 45 0c 8b 85 90 01 04 03 c1 b9 8e 0a 00 00 f7 f1 90 00 } //01 00 
		$a_81_2 = {63 51 36 65 63 6b 39 65 31 64 58 65 52 66 4e 77 52 30 6b 34 39 68 4b 4d 38 54 52 50 56 68 66 61 6b 68 } //00 00 
	condition:
		any of ($a_*)
 
}