
rule Ransom_Win64_Clop_SM_dha{
	meta:
		description = "Ransom:Win64/Clop.SM!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 41 00 5f 00 54 00 45 00 58 00 54 00 5f 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 5f 00 41 00 2e 00 54 00 58 00 54 00 } //1 %s\A_TEXT_READ_ME_A.TXT
		$a_01_1 = {25 00 73 00 20 00 72 00 75 00 6e 00 72 00 75 00 6e 00 } //1 %s runrun
		$a_01_2 = {2e 00 43 00 4c 00 5f 00 30 00 5f 00 50 00 } //1 .CL_0_P
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}