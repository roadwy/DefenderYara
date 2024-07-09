
rule Ransom_Win32_Reveton_Q{
	meta:
		description = "Ransom:Win32/Reveton.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 93 00 05 00 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8a 93 00 06 00 00 88 10 a1 ?? ?? ?? ?? 8a 93 01 06 00 00 88 10 a1 ?? ?? ?? ?? 8b 93 02 06 00 00 89 10 } //2
		$a_01_1 = {46 42 49 20 2d 20 43 6f 6d 70 75 74 65 72 20 6c 6f 63 6b 65 64 2e } //1 FBI - Computer locked.
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}