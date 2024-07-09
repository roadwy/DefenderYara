
rule Ransom_Win32_Cerber_F{
	meta:
		description = "Ransom:Win32/Cerber.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6b c9 0d d3 f8 8b 4c 24 04 d3 e0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 99 c3 } //1
		$a_03_1 = {c7 03 44 72 62 52 66 89 43 0f ff 15 ?? ?? ?? ?? 8d 44 00 02 66 89 43 06 } //1
		$a_03_2 = {75 02 0f 31 8b 15 ?? ?? ?? ?? 6b f6 64 8b c8 c1 e1 0b 33 c8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}