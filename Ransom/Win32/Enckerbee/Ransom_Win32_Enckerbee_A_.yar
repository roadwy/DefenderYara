
rule Ransom_Win32_Enckerbee_A_{
	meta:
		description = "Ransom:Win32/Enckerbee.A!!Enckerbee.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {21 21 21 21 20 41 54 54 45 4e 54 49 4f 4e 20 21 21 21 21 20 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 20 21 21 21 21 } //!!!! ATTENTION !!!!  YOUR FILES HAVE BEEN ENCRYPTED! !!!!  1
		$a_80_1 = {5c 52 39 38 30 5c 52 65 6c 65 61 73 65 5c 52 39 38 30 2e 70 64 62 } //\R980\Release\R980.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}