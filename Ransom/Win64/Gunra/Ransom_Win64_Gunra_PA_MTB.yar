
rule Ransom_Win64_Gunra_PA_MTB{
	meta:
		description = "Ransom:Win64/Gunra.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 45 00 4e 00 43 00 52 00 54 00 } //1 .ENCRT
		$a_01_1 = {21 21 21 44 41 4e 47 45 52 20 21 21 21 } //1 !!!DANGER !!!
		$a_01_2 = {59 4f 55 52 20 41 4c 4c 20 44 41 54 41 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 } //2 YOUR ALL DATA HAVE BEEN ENCRYPTED!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}