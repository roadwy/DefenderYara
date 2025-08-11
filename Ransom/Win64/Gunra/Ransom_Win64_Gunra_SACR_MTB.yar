
rule Ransom_Win64_Gunra_SACR_MTB{
	meta:
		description = "Ransom:Win64/Gunra.SACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {21 21 21 44 41 4e 47 45 52 20 21 21 21 } //2 !!!DANGER !!!
		$a_81_1 = {44 4f 20 4e 4f 54 20 4d 4f 44 49 46 59 20 6f 72 20 74 72 79 20 74 6f 20 52 45 43 4f 56 45 52 20 61 6e 79 20 66 69 6c 65 73 20 79 6f 75 72 73 65 6c 66 2e 57 65 20 57 49 4c 4c 20 4e 4f 54 20 62 65 20 61 62 6c 65 20 74 6f 20 52 45 53 54 4f 52 45 20 74 68 65 6d 2e } //1 DO NOT MODIFY or try to RECOVER any files yourself.We WILL NOT be able to RESTORE them.
		$a_81_2 = {59 4f 55 52 20 41 4c 4c 20 44 41 54 41 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 21 } //1 YOUR ALL DATA HAVE BEEN ENCRYPTED!
		$a_81_3 = {59 6f 75 20 63 61 6e 20 64 65 63 72 79 70 74 20 73 6f 6d 65 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 20 77 68 65 6e 20 79 6f 75 20 63 6f 6e 74 61 63 74 20 75 73 } //1 You can decrypt some of your files for free when you contact us
		$a_81_4 = {52 33 41 44 4d 33 2e 74 78 74 } //1 R3ADM3.txt
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}