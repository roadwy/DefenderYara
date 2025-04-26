
rule Trojan_Win32_Gularger_F_dha{
	meta:
		description = "Trojan:Win32/Gularger.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 08 0f b6 45 ff 83 c0 01 99 f7 7d 0c 88 55 ff eb 8f 8b e5 5d c3 } //2
		$a_03_1 = {6a 02 8b 45 08 50 8d 4d fc 51 e8 ?? ?? ?? ?? 83 c4 0c 6a 02 8b 55 08 83 c2 02 52 8d 85 d4 f6 ff ff 50 e8 ?? ?? ?? ?? 83 c4 0c 81 7d fc 00 08 00 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}