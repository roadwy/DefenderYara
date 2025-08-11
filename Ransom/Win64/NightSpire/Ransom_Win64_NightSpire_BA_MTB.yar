
rule Ransom_Win64_NightSpire_BA_MTB{
	meta:
		description = "Ransom:Win64/NightSpire.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 73 65 6e 73 65 74 69 76 65 20 64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your sensetive data are stolen and encrypted!
		$a_81_1 = {41 66 74 65 72 20 74 68 61 74 20 77 65 20 77 69 6c 6c 20 70 75 62 6c 69 63 20 74 68 69 73 20 73 69 74 75 61 74 69 6f 6e 20 61 6e 64 20 61 6c 6c 20 64 61 74 61 2e } //1 After that we will public this situation and all data.
		$a_81_2 = {44 4f 20 4e 4f 54 20 4d 4f 44 49 46 59 20 46 49 4c 45 53 20 59 4f 55 52 53 45 4c 46 2e } //1 DO NOT MODIFY FILES YOURSELF.
		$a_81_3 = {44 4f 20 4e 4f 54 20 55 53 45 20 54 48 49 52 44 20 50 41 52 54 59 20 53 4f 46 54 57 41 52 45 20 54 4f 20 52 45 53 54 4f 52 45 20 59 4f 55 52 20 44 41 54 41 2e } //1 DO NOT USE THIRD PARTY SOFTWARE TO RESTORE YOUR DATA.
		$a_81_4 = {6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //1 onionmail.org
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}