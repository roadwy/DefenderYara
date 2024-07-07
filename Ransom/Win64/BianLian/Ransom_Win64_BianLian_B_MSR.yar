
rule Ransom_Win64_BianLian_B_MSR{
	meta:
		description = "Ransom:Win64/BianLian.B!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 73 79 73 74 65 6d 73 20 77 65 72 65 20 61 74 74 61 63 6b 65 64 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //Your network systems were attacked and encrypted  1
		$a_01_1 = {4c 6f 6f 6b 20 61 74 20 74 68 69 73 20 69 6e 73 74 72 75 63 74 69 6f 6e 2e 74 78 74 } //1 Look at this instruction.txt
		$a_01_2 = {62 69 61 6e 6c 69 61 6e } //1 bianlian
		$a_01_3 = {74 65 78 74 3d 20 20 7a 6f 6d 62 69 65 } //1 text=  zombie
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}