
rule Ransom_Win64_Sicarii_AHB_MTB{
	meta:
		description = "Ransom:Win64/Sicarii.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6e 66 65 63 74 5f 69 64 } //10 infect_id
		$a_01_1 = {52 45 41 44 4d 45 5f 53 49 43 41 52 49 49 5f 4c 4f 43 4b 45 44 2e 74 78 74 } //20 README_SICARII_LOCKED.txt
		$a_01_2 = {6e 65 74 20 75 73 65 72 20 53 69 63 61 72 69 75 73 } //30 net user Sicarius
		$a_01_3 = {61 77 73 20 69 61 6d 20 63 72 65 61 74 65 2d 75 73 65 72 20 2d 2d 75 73 65 72 2d 6e 61 6d 65 20 53 69 63 61 72 69 75 73 } //40 aws iam create-user --user-name Sicarius
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}