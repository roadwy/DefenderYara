
rule Ransom_Win64_Lcry_MK_MTB{
	meta:
		description = "Ransom:Win64/Lcry.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {4c 43 52 59 5f 57 41 4c 4c 2e 62 6d 70 } //LCRY_WALL.bmp  1
		$a_80_1 = {4c 43 52 59 20 52 41 4e 53 4f 4d 57 41 52 45 } //LCRY RANSOMWARE  1
		$a_80_2 = {4c 43 52 59 5f 4d 41 43 48 49 4e 45 49 44 2e 49 44 } //LCRY_MACHINEID.ID  1
		$a_80_3 = {59 4f 55 20 41 52 45 20 4e 4f 57 20 56 49 43 54 49 4d 20 4f 46 20 4c 43 52 59 20 52 41 4e 53 4f 4d 57 41 52 45 } //YOU ARE NOW VICTIM OF LCRY RANSOMWARE  1
		$a_80_4 = {4c 43 52 59 5f 52 45 41 44 4d 45 2e 74 78 74 } //LCRY_README.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}