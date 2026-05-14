
rule Ransom_Win64_PetyaX_AMTB{
	meta:
		description = "Ransom:Win64/PetyaX!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {50 65 74 79 61 58 57 50 46 2e 44 65 63 72 79 70 74 57 69 6e 64 6f 77 } //PetyaXWPF.DecryptWindow  1
		$a_80_1 = {50 65 74 79 61 58 2e 64 6c 6c } //PetyaX.dll  1
		$a_80_2 = {43 6f 6e 74 61 63 74 20 75 73 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //Contact us for decryption key  1
		$a_80_3 = {45 6e 63 72 79 70 74 65 64 20 46 69 6c 65 73 20 28 2a 2e 70 65 74 79 61 78 29 7c 2a 2e 70 65 74 79 61 78 } //Encrypted Files (*.petyax)|*.petyax  1
		$a_80_4 = {50 65 74 79 61 58 2e 70 64 62 } //PetyaX.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}