
rule Ransom_Win32_Locky_I{
	meta:
		description = "Ransom:Win32/Locky.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f 00 4c 00 6f 00 63 00 6b 00 79 00 5f 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 69 00 6e 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 74 00 78 00 74 00 } //1 _Locky_recover_instructions.txt
		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 20 00 2f 00 41 00 6c 00 6c 00 } //1 Delete Shadows /Quiet /All
		$a_01_2 = {77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 } //1 wallet.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}