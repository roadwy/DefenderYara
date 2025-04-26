
rule Trojan_Win64_Solorigate_SC_dha{
	meta:
		description = "Trojan:Win64/Solorigate.SC!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 80 0f b6 03 03 c9 32 c1 0f b6 c0 66 0f 6e c0 f3 0f e6 c0 f2 0f 5e c6 f2 0f 2c c0 88 03 e8 ?? ?? ?? ?? 6b c8 ?? ff c7 00 0b e8 ?? ?? ?? ?? 8d 0c 80 c1 e1 02 3b f9 7c c1 } //1
		$a_03_1 = {44 8b c0 48 8d 5b 01 b8 ?? ?? ?? ?? 41 f7 e8 41 03 d0 c1 fa 06 8b ca c1 e9 1f 03 d1 6b ca ?? 44 2b c1 41 83 c0 02 44 00 43 ff 48 83 ef 01 75 ?? ?? ?? ?? ?? ?? ?? 8d 8e ?? ?? 00 00 2b c8 85 c9 7f ac } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}