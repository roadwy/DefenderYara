
rule Ransom_Win32_Ryuk_A_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a c8 32 4d ?? [0-0b] 88 4d } //1
		$a_03_1 = {8a 45 ef 3b ?? 75 ?? [0-04] 88 01 } //1
		$a_03_2 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 ?? 8b 44 24 04 f7 e1 c2 ?? ?? 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2 } //1
		$a_00_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}