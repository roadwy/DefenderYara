
rule Trojan_Win32_Tadefia_A_bit{
	meta:
		description = "Trojan:Win32/Tadefia.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {d3 e0 8b cf f7 d9 8b ?? ?? d3 ?? 0b c2 89 ?? ?? 8b ?? ?? 33 } //5
		$a_01_1 = {54 68 69 73 20 66 69 6c 65 20 63 72 65 61 74 65 64 20 62 79 20 74 72 69 61 6c 20 76 65 72 73 69 6f 6e 20 6f 66 20 51 75 69 63 6b 20 42 61 74 63 68 20 46 69 6c 65 20 43 6f 6d 70 69 6c 65 72 } //5 This file created by trial version of Quick Batch File Compiler
		$a_03_2 = {66 6f 72 6d 61 74 20 ?? 3a } //1
		$a_01_3 = {72 64 20 2f 73 20 2f 71 20 63 3a 5c } //1 rd /s /q c:\
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}