
rule Ransom_Win32_Basta_BB_MTB{
	meta:
		description = "Ransom:Win32/Basta.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 8b 0d 30 00 00 00 8b 49 0c 8b 49 0c } //1
		$a_01_1 = {67 69 74 36 36 5c 64 6c 6c 5f 72 65 6c 65 61 73 65 5c 44 69 74 68 65 72 2e 70 64 62 } //1 git66\dll_release\Dither.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}