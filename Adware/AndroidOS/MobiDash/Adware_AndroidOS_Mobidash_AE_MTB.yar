
rule Adware_AndroidOS_Mobidash_AE_MTB{
	meta:
		description = "Adware:AndroidOS/Mobidash.AE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 41 70 70 79 54 65 63 68 2f 61 70 70 79 74 65 63 68 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 com/AppyTech/appytech/MainActivity
		$a_01_1 = {44 45 4d 41 4e 44 45 5f 53 54 4f 52 41 47 45 5f 54 4f 5f 44 41 54 41 } //1 DEMANDE_STORAGE_TO_DATA
		$a_01_2 = {4e 4f 4d 5f 4c 49 53 54 45 5f 47 52 49 44 5f 43 4f 50 59 } //1 NOM_LISTE_GRID_COPY
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}