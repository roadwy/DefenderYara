
rule Ransom_Win32_Paradise_BA_MTB{
	meta:
		description = "Ransom:Win32/Paradise.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {50 61 72 61 64 69 73 65 20 76 31 2e 30 30 } //1 Paradise v1.00
		$a_03_1 = {56 69 72 75 73 20 73 69 7a 65 90 02 20 62 79 74 65 73 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}