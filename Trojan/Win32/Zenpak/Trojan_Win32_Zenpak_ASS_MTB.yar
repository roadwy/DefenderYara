
rule Trojan_Win32_Zenpak_ASS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 04 6b c2 ?? 8b 4c 24 ?? 29 c1 89 c8 83 e8 03 89 4c 24 ?? 89 44 24 } //1
		$a_01_1 = {64 00 35 00 42 00 6c 00 65 00 73 00 73 00 65 00 64 00 59 00 69 00 73 00 6e 00 2e 00 74 00 66 00 73 00 70 00 69 00 72 00 69 00 74 00 34 00 73 00 68 00 65 00 2e 00 64 00 6a 00 } //1 d5BlessedYisn.tfspirit4she.dj
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}