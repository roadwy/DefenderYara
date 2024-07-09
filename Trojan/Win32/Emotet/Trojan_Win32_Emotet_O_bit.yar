
rule Trojan_Win32_Emotet_O_bit{
	meta:
		description = "Trojan:Win32/Emotet.O!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {66 83 f8 41 72 0e 66 83 f8 5a 77 08 0f b7 c0 83 c0 20 eb 03 0f b7 c0 69 d2 ?? ?? ?? ?? 03 d0 83 c1 02 0f b7 01 } //1
		$a_01_1 = {64 a1 30 00 00 00 53 56 57 8b 78 0c 8b d9 83 c7 0c 8b 37 } //1
		$a_01_2 = {0f be c0 03 c8 42 8a 02 84 c0 75 ee 8b 45 f8 33 4d 0c 33 ff } //1
		$a_01_3 = {c1 ef 02 33 c0 8d 0c bb 8b fe 8b d1 2b d3 83 c2 03 c1 ea 02 3b d9 0f 47 d0 85 d2 74 3b } //1
		$a_01_4 = {8d 5b 04 33 4d 08 0f b6 c1 66 89 07 8b c1 c1 e8 08 8d 7f 08 0f b6 c0 66 89 47 fa c1 e9 10 0f b6 c1 c1 e9 08 46 66 89 47 fc 0f b6 c1 66 89 47 fe 3b f2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}