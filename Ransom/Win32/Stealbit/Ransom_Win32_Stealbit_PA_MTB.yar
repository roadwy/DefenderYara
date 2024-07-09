
rule Ransom_Win32_Stealbit_PA_MTB{
	meta:
		description = "Ransom:Win32/Stealbit.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 81 ec [0-04] f6 40 68 70 56 74 ?? eb } //1
		$a_03_1 = {33 c9 8b c1 83 e0 0f 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 f9 7c 72 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}