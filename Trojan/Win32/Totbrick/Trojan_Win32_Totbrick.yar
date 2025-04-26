
rule Trojan_Win32_Totbrick{
	meta:
		description = "Trojan:Win32/Totbrick,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d4 b8 04 0b 40 00 41 89 15 ?? ?? 44 00 03 c1 ff d0 4a 4a 8d 0d ?? ?? 44 00 51 4a 4a e8 ?? ?? fd ff 8b f1 48 } //2
		$a_03_1 = {89 54 24 08 b8 ?? 00 00 00 89 44 24 04 ba 14 00 00 00 89 54 24 0c 51 e9 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}