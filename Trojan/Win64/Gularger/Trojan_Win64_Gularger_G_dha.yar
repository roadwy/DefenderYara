
rule Trojan_Win64_Gularger_G_dha{
	meta:
		description = "Trojan:Win64/Gularger.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 24 20 83 c0 01 99 f7 7c 24 58 88 54 24 20 e9 74 ff ff ff 48 83 c4 48 c3 } //2
		$a_01_1 = {44 0f b6 5c 24 21 48 8b 44 24 38 42 0f b6 14 18 0f b6 4c 24 20 48 8b 44 24 38 0f b6 0c 08 8b c2 03 c1 99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}