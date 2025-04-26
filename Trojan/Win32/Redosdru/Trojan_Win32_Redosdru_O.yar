
rule Trojan_Win32_Redosdru_O{
	meta:
		description = "Trojan:Win32/Redosdru.O,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {47 c6 44 24 ?? 68 c6 44 24 ?? 30 c6 44 24 ?? 73 8b 54 24 ?? 8d 8e ?? ?? 00 00 89 86 ?? ?? 00 00 b0 74 } //2
		$a_01_1 = {43 00 56 00 69 00 64 00 65 00 6f 00 43 00 61 00 70 00 } //1 CVideoCap
		$a_01_2 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 6d 00 6f 00 75 00 73 00 65 00 20 00 25 00 64 00 } //1 Global\mouse %d
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}