
rule Trojan_AndroidOS_Spynote_OT{
	meta:
		description = "Trojan:AndroidOS/Spynote.OT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 64 6d 7a 7a 78 61 67 71 61 6b 73 6a 67 61 70 65 65 75 6f 72 74 76 69 70 76 75 64 6c 70 63 76 6a 63 75 68 68 70 75 69 6b 65 73 71 6d 62 79 6c 66 6a 32 32 4f 76 65 72 } //1 ddmzzxagqaksjgapeeuortvipvudlpcvjcuhhpuikesqmbylfj22Over
		$a_01_1 = {69 74 73 64 76 71 6a 6b 69 64 31 30 31 36 } //1 itsdvqjkid1016
		$a_01_2 = {6a 66 6a 6d 6f 68 69 66 67 6d 31 30 32 32 } //1 jfjmohifgm1022
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}