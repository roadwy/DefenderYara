
rule Ransom_AndroidOS_Slocker_C_MTB{
	meta:
		description = "Ransom:AndroidOS/Slocker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 68 65 6e 62 69 62 69 2e 68 65 69 6d 61 } //1 chenbibi.heima
		$a_00_1 = {6c 6f 63 6b 4e 6f 77 } //1 lockNow
		$a_00_2 = {42 6c 61 63 6b 43 6f 64 65 73 63 68 65 6e 62 62 } //1 BlackCodeschenbb
		$a_00_3 = {4d 79 51 51 } //1 MyQQ
		$a_00_4 = {46 75 63 6b 59 6f 75 } //1 FuckYou
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}