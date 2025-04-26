
rule Ransom_Win32_Genasom_F{
	meta:
		description = "Ransom:Win32/Genasom.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b2 65 6a 00 b3 5c 51 88 54 24 ?? 88 54 24 ?? 88 54 24 ?? 88 54 24 ?? 88 54 24 ?? 88 54 24 ?? 8b 15 ?? ?? 40 00 68 01 00 00 80 c6 44 24 ?? 53 c6 44 24 ?? 66 c6 44 24 ?? 74 c6 44 24 ?? 77 c6 44 24 ?? 61 } //1
		$a_02_1 = {5c c6 44 24 ?? 52 c6 44 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}